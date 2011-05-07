#include <Windows.h>
#include <Psapi.h>
#include <Shobjidl.h>

#define DllExport               __declspec( dllexport )

#define MAX_PROCESSES           200
#define MAX_APP_USER_ID_LENGTH  128
//#define ACCESS_FLAGS            PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION | PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ
#define ACCESS_FLAGS            PROCESS_ALL_ACCESS
#define PROCESS_PATH            "C:\\Windows\\system32\\notepad.exe"
#define PROCESS_APP_USER_ID     L"Microsoft.Windows.AlexNotepad"
#define MARKABLE                static
#define MARK_SIZE(name)         static void name##_MarkEnd() { } \
                                static const UINT name##Size = ((UINT)&name##_MarkEnd - (UINT)&name);
#define FAIL(message)           MessageBox( NULL, message, "Error", MB_ICONERROR ); return
#define FAIL_IF(exp, message)   if( exp ) { FAIL( message ); }

typedef HRESULT (STDAPICALLTYPE *SETCURRENTPROCESSEXPLICITAPPUSERMODELID)(PCWSTR AppID);

struct InjectData
{
    SETCURRENTPROCESSEXPLICITAPPUSERMODELID setCurrentProcessExplicitAppUserModelID;

    WCHAR id[MAX_APP_USER_ID_LENGTH];
};

MARKABLE DWORD WINAPI ThreadFunc( InjectData *pData )
{
    pData->setCurrentProcessExplicitAppUserModelID( pData->id );

    return 0;
}
MARK_SIZE(ThreadFunc)

static void SetRemoteProcessExplicitAppUserModelID( HANDLE process, PCWSTR id )
{
    InjectData params;
    params.setCurrentProcessExplicitAppUserModelID = &SetCurrentProcessExplicitAppUserModelID;
    wcscpy( params.id, id );

    InjectData *pRemoteData = (InjectData *)VirtualAllocEx( process, 0, sizeof(InjectData), MEM_COMMIT, PAGE_READWRITE );
    FAIL_IF( pRemoteData == NULL, "Failed to allocate data block." );

    BOOL result = WriteProcessMemory( process, pRemoteData, &params, sizeof(InjectData), NULL );
    FAIL_IF( result == FALSE, "Failed to copy data block." );

    DWORD *pRemoteCode = (PDWORD)VirtualAllocEx( process, 0, ThreadFuncSize, MEM_COMMIT, PAGE_EXECUTE_READWRITE );
    FAIL_IF( pRemoteCode == NULL, "Failed to allocate code block." );

    result = WriteProcessMemory( process, pRemoteCode, &ThreadFunc, ThreadFuncSize, NULL );
    FAIL_IF( result == FALSE, "Failed to copy code block." );

    HANDLE thread = CreateRemoteThread( process, NULL, 0, (LPTHREAD_START_ROUTINE)pRemoteCode, pRemoteData, 0, NULL );
    DWORD error;
    if( thread == NULL )
    {
        error = GetLastError();
    }
    FAIL_IF( thread == NULL, "Failed to create thread." );
}

static void MonitorProcessesInternal()
{
    while( true )
    {
        DWORD bytesUsed;
        DWORD processIDs[MAX_PROCESSES];
        EnumProcesses( processIDs, sizeof( processIDs ), &bytesUsed );
        DWORD processCount = bytesUsed / sizeof( DWORD );

        for( DWORD i = 0; i < processCount; ++i )
        {
            HANDLE process = OpenProcess( ACCESS_FLAGS, FALSE, processIDs[i] );

            if( process == NULL ) { continue; }

            char buf[MAX_PATH];
            DWORD bufSize = sizeof( buf );
            QueryFullProcessImageName( process, 0, buf, &bufSize );
            if( _stricmp(buf, PROCESS_PATH) == 0 )
            {
                //MessageBox( NULL, "found the process", "Caption", MB_ICONINFORMATION );
                SetRemoteProcessExplicitAppUserModelID( process, PROCESS_APP_USER_ID );
                CloseHandle( process );
                break;
            }

            CloseHandle( process );
        }

        Sleep( 100 );

        break;
    }
}

extern "C"
{
    DllExport void MonitorProcesses( void )
    {
        MonitorProcessesInternal();
    }
}