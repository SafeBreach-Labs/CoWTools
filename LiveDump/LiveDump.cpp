#include "LiveDump.hpp"
// Based on the code: https://code.google.com/archive/p/livedump/
// License: GNU GPL v3


//
// Globals
//
static NtSystemDebugControl g_NtSystemDebugControl = NULL;

///=========================================================================
/// PrintUsage()
///
/// <summary>
/// Print program usage
/// </summary>
/// <returns></returns>
/// <remarks>
/// </remarks>
///========================================================================= 
VOID
PrintUsage(
    VOID
)
{
    printf("\n\n");
    printf("LiveDump.exe [type] [options] <FileName>\n");
    printf("Type:\n");
    printf("\ttriage : create a triage dump (parameter 29)\n");
    printf("\tkernel : create a kernel dump (parameter 37)\n");
    printf("Options (triage dump only):\n");
    printf("\t-p : PID to dump\n");
    printf("Options (kernel dump only):\n");
    printf("\t-c : compress memory pages in dump\n");
    printf("\t-d : Use dump stack (currently not implemented in Windows 8.1, 9600.16404.x86fre.winblue_gdr.130913-2141)\n");
    printf("\t-h : add hypervisor pages\n");
    printf("\t-u : also dump user space memory\n");
    printf("\t-O : <page as long> <flags> \n");
    printf("FileName is the full path to the dump file to create.");
    printf("\n");
}

///=========================================================================
/// main()
///
/// <summary>
/// Main console program
/// </summary>
/// <returns>0 on success, other values on failure</returns>
/// <remarks>
/// </remarks>
///========================================================================= 
INT
wmain(
    __in INT Argc,
    __in PWCHAR Argv[]
)
{
    HANDLE handle;
    HMODULE module;
    DWORD result;
    INT i;
    SYSDBG_LIVEDUMP_CONTROL_FLAGS flags;
    SYSDBG_LIVEDUMP_CONTROL_ADDPAGES pages;
    PWCHAR outfile;
    PWCHAR type;
    NTSTATUS status;
    ULONG pid;
    ULONG fileFlags;

    handle = INVALID_HANDLE_VALUE;
    result = NO_ERROR;
    flags.AsUlong = 0;
    pages.AsUlong = 0;
    outfile = NULL;
    type = NULL;
    pid = 0;

    //
    // Parse and validate arguments
    //
    if (Argc < 3)
    {
        printf("Invalid number of arguments.");
        PrintUsage();
        return 1;
    }

    for (i = 1; i < Argc; ++i)
    {
        if (i == 1)
        {
            type = Argv[i];
            continue;
        }

        if (_wcsicmp(Argv[i], L"-c") == 0)
        {
            flags.CompressMemoryPagesData = 1;
        }
        else if (_wcsicmp(Argv[i], L"-d") == 0)
        {
            flags.UseDumpStorageStack = 1;
        }
        else if (_wcsicmp(Argv[i], L"-h") == 0)
        {
            pages.HypervisorPages = 1;
        }
        else if (_wcsicmp(Argv[i], L"-u") == 0)
        {
            flags.IncludeUserSpaceMemoryPages = 1;
        }
        else if (_wcsicmp(Argv[i], L"-O") == 0)
        {
            if ((i + 3) >= Argc)
            {
                printf("You must specify a page value.\n");
                PrintUsage();
                return 1;
            }
            pages.AsUlong = _wtoi(Argv[++i]);
            flags.AsUlong = _wtoi(Argv[++i]);
            outfile = Argv[++i];
            break;
        }
        else
        {
            outfile = Argv[i];
        }
    }

    if (outfile == NULL)
    {
        printf("You must specify a file name.\n");
        PrintUsage();
        return 1;
    }

    if (_wcsicmp(type, L"triage") == 0)
    {
        //
        // WriteFile can't cope with buffers that aren't sector-aligned when we specify
        // FILE_FLAG_NO_BUFFERING (which is a requirement for kernel dump creation).  
        // Since the returned triage buffer data can be unaligned in this manner, it's
        // easiest to just prevent WriteFile failing by not specifying that flag during
        // the call to CreateFile.
        //
        fileFlags = FILE_ATTRIBUTE_NORMAL;

        if (pid == 0)
        {
            printf("A non-zero PID is required for triage dumps.\n");
            PrintUsage();
            return 1;
        }
    }
    else if (_wcsicmp(type, L"kernel") == 0)
    {
        //
        // We have to use synchronous/no-buffering I/O for kernel dump creation.
        //
        fileFlags = FILE_FLAG_WRITE_THROUGH | FILE_FLAG_NO_BUFFERING;
    }
    else
    {
        printf("Valid dump types are 'triage' and 'kernel'.\n");
        PrintUsage();
        return 1;
    }

    //
    // Get function addresses
    //
    module = LoadLibrary(L"ntdll.dll");

    if (module == NULL)
    {
        printf("Failed to load ntdll.dll\n");
        return -1;
    }

    g_NtSystemDebugControl = (NtSystemDebugControl) GetProcAddress(module, "NtSystemDebugControl");
    FreeLibrary(module);
    if (g_NtSystemDebugControl == NULL)
    {
        printf("Failed to resolve NtSystemDebugControl.\n");
        return 1;
    }

    //
    // Get SeDebugPrivilege
    //
    if (!EnablePrivilege(SE_DEBUG_NAME, TRUE))
    {
        result = GetLastError();
        printf("Failed to enable SeDebugPrivilege:  %lu\n", result);
        goto Exit;
    }

    //
    // Create the target file (must specify synchronous I/O)
    //
    handle = CreateFileW(outfile,
        GENERIC_WRITE | GENERIC_READ,
        0,
        NULL,
        CREATE_ALWAYS,
        fileFlags,
        NULL);

    if (handle == INVALID_HANDLE_VALUE)
    {
        result = GetLastError();
        printf("CreateFileW failed: %d\n", result);
        goto Exit;
    }

    //
    // Try to create the requested dump
    //
    if (_wcsicmp(type, L"triage") == 0)
    {
        status = CreateTriageDump(handle, pid);
    }
    else if (_wcsicmp(type, L"kernel") == 0)
    {
        status = CreateKernelDump(handle, flags, pages);
    }

    if (NT_SUCCESS(status))
    {
        printf("Dump file '%ws' written successfully!\n", outfile);
        result = NO_ERROR;
    }
    else
    {
        printf("Failed to create dump file.\n");
        result = -1;
    }

Exit:

    //
    // Remove privileges regardless of earlier success.
    //
    EnablePrivilege(SE_DEBUG_NAME, FALSE);

    if (handle != INVALID_HANDLE_VALUE)
    {
        CloseHandle(handle);

        if (!NT_SUCCESS(status))
        {
            DeleteFile(outfile);
        }
    }

    return (result == NO_ERROR) ? 0 : 1;
}

///=========================================================================
/// EnablePrivilege()
///
/// <summary>
/// Enables or disables a privilege in an access token
/// </summary>
/// <parameter>PrivilegeName - name of privilege</parameter>
/// <parameter>Acquire - TRUE to add, FALSE to remove</parameter>
/// <returns>TRUE on success, FALSE on failure</returns>
/// <remarks>
/// </remarks>
///========================================================================= 
BOOL
EnablePrivilege(
    __in PCWSTR PrivilegeName,
    __in BOOLEAN Acquire
)
{
    HANDLE tokenHandle;
    BOOL ret;
    ULONG tokenPrivilegesSize = FIELD_OFFSET(TOKEN_PRIVILEGES, Privileges[1]);
    PTOKEN_PRIVILEGES tokenPrivileges = static_cast<PTOKEN_PRIVILEGES>(calloc(1, tokenPrivilegesSize));

    if (tokenPrivileges == NULL)
    {
        printf("Failed to allocate token privileges structure\n");
        return FALSE;
    }

    tokenHandle = NULL;
    tokenPrivileges->PrivilegeCount = 1;
    ret = LookupPrivilegeValue(NULL,
        PrivilegeName,
        &tokenPrivileges->Privileges[0].Luid);
    if (ret == FALSE)
    {
        printf("Failed to lookup privilege value by name:  %lu\n", GetLastError());
        goto Exit;
    }

    tokenPrivileges->Privileges[0].Attributes = Acquire ? SE_PRIVILEGE_ENABLED
        : SE_PRIVILEGE_REMOVED;

    ret = OpenProcessToken(GetCurrentProcess(),
        TOKEN_ADJUST_PRIVILEGES,
        &tokenHandle);
    if (ret == FALSE)
    {
        printf("Failed to open current process token:  %lu\n", GetLastError());
        goto Exit;
    }

    ret = AdjustTokenPrivileges(tokenHandle,
        FALSE,
        tokenPrivileges,
        tokenPrivilegesSize,
        NULL,
        NULL);
    if (ret == FALSE)
    {
        printf("Failed to adjust current process token privileges:  %lu\n", GetLastError());
        goto Exit;
    }

Exit:

    if (tokenHandle != NULL)
    {
        CloseHandle(tokenHandle);
    }

    free(tokenPrivileges);

    return ret;
}

///=========================================================================
/// CreateTriageDump()
///
/// <summary>
/// Creates a triage dump using NtDebugSystemControl parameter 29 and the 
/// first 16 threads of the supplied process.
/// </summary>
/// <parameter>FileHandle - Handle to dump file to write</parameter>
/// <parameter>Pid - ID of the process to dump</parameter>
/// <returns>NTSTATUS code</returns>
/// <remarks>
/// </remarks>
///========================================================================= 
NTSTATUS
CreateTriageDump(
    __in HANDLE FileHandle,
    __in ULONG Pid
)
{
    NTSTATUS status;
    SYSDBG_TRIAGE_DUMP dump;
    PUCHAR dumpData;
    ULONG returnLength;
    ULONG bytesWritten;
    HANDLE enumHandle;
    THREADENTRY32 thread;
    HANDLE threadHandles[MAX_TRIAGE_THREADS];
    INT threadCount;
    HANDLE threadHandle;
    HANDLE processHandle;

    printf("Attempting to create a triage dump...\n");
    enumHandle = NULL;
    dumpData = NULL;
    threadCount = 0;
    status = -1;

    //
    // Open the process
    //
    processHandle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, Pid);

    if (processHandle == INVALID_HANDLE_VALUE)
    {
        printf("Failed to open PID %lu: %lu", Pid, GetLastError());
        goto Exit;
    }

    //
    // Enumerate the first 16 threads
    //
    enumHandle = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, Pid);

    if (enumHandle == INVALID_HANDLE_VALUE)
    {
        printf("Failed to get thread list:  %lu", GetLastError());
        goto Exit;
    }

    thread.dwSize = sizeof(thread);

    if (!Thread32First(enumHandle, &thread))
    {
        printf("Failed to get first thread:  %lu", GetLastError());
        goto Exit;
    }

    do
    {
        if (thread.dwSize >=
            FIELD_OFFSET(THREADENTRY32, th32OwnerProcessID) +
            sizeof(thread.th32OwnerProcessID))
        {
            threadHandle = OpenThread(THREAD_ALL_ACCESS, FALSE, thread.th32ThreadID);

            if (threadHandle == INVALID_HANDLE_VALUE)
            {
                printf("Failed to open thread %lu, skipping.\n", thread.th32ThreadID);
                continue;
            }

            threadHandles[threadCount++] = threadHandle;
        }

    } while ((Thread32Next(enumHandle, &thread)) && threadCount < MAX_TRIAGE_THREADS);

    if (threadCount == 0)
    {
        printf("No suitable threads found in PID %lu\n", Pid);
        goto Exit;
    }

    printf("Triage dump is for PID %lu with %lu threads.\n",
        Pid,
        threadCount);
    //
    // Allocate buffer for triage dump data
    //
    dumpData = (PUCHAR)(calloc(1, TRIAGE_SIZE));

    if (dumpData == NULL)
    {
        printf("Failed to allocate %lu bytes\n", TRIAGE_SIZE);
        goto Exit;
    }

    memset(&dump, 0, sizeof(dump));
    memset(dumpData, 0, TRIAGE_SIZE);

    dump.ThreadHandles = threadCount;
    dump.Handles = &threadHandles[0];

    assert(g_NtSystemDebugControl != NULL);
    status = g_NtSystemDebugControl(CONTROL_TRIAGE_DUMP,
        (PVOID)(&dump),
        sizeof(dump),
        dumpData,
        TRIAGE_SIZE,
        &returnLength);

    if (!NT_SUCCESS(status))
    {
        printf("NtSystemDebugControl failed:  %08x\n", status);
        goto Exit;
    }

    if (returnLength == 0)
    {
        printf("Triage data buffer is empty.  Try a different process.\n");
        status = -1;
        goto Exit;
    }

    //
    // Write to target dump file
    //
    if (!WriteFile(FileHandle, dumpData, returnLength, &bytesWritten, NULL))
    {
        printf("WriteFile failed:  %lu\n", GetLastError());
        status = -1;
        goto Exit;
    }

    assert(bytesWritten == returnLength);

Exit:

    if (enumHandle != INVALID_HANDLE_VALUE)
    {
        CloseHandle(enumHandle);
    }

    for (INT i = 0; i <= threadCount; i++)
    {
        CloseHandle(threadHandles[i]);
    }

    if (processHandle != INVALID_HANDLE_VALUE)
    {
        CloseHandle(processHandle);
    }

    if (dumpData != NULL)
    {
        free(dumpData);
    }

    return status;
}

///=========================================================================
/// CreateKernelDump()
///
/// <summary>
/// Creates a kernel dump using NtDebugSystemControl parameter 37
/// </summary>
/// <parameter>FileHandle - Handle to dump file to write</parameter>
/// <parameter>Flags - Kernel dump flags</parameter>
/// <parameter>Pages - Flags for memory pages to write</parameter>
/// <returns>NTSTATUS code</returns>
/// <remarks>
/// </remarks>
///========================================================================= 
NTSTATUS
CreateKernelDump(
    __in HANDLE FileHandle,
    __in SYSDBG_LIVEDUMP_CONTROL_FLAGS Flags,
    __in SYSDBG_LIVEDUMP_CONTROL_ADDPAGES Pages
)
{
    NTSTATUS status;
    SYSDBG_LIVEDUMP_CONTROL liveDumpControl;
    ULONG returnLength;

    printf("Attempting to create a kernel dump with flags %08x and pages %08x... size sysdbg live dump %llu sizeof flags: %08x, sizeof addpagess: %08x\n",
        Flags,
        Pages,
        sizeof(liveDumpControl),
        sizeof(Flags),
        sizeof(Pages));
    printf("Please be patient, this could take a minute or two...\n");

    memset(&liveDumpControl, 0, sizeof(liveDumpControl));

    //
    // The only thing the kernel looks at in the struct we pass is the handle,
    // the flags and the pages to dump.
    //
    liveDumpControl.DumpFileHandle = (PVOID)(FileHandle);
    liveDumpControl.AddPagesControl = Pages;
    liveDumpControl.Flags = Flags;
    unsigned char* pf = ((unsigned char*)&liveDumpControl);
    void* raw_ptr = &liveDumpControl;
    ((void**)raw_ptr)[0] = (PVOID)(Pages.AsUlong);
    ((void**)raw_ptr)[5] = (PVOID)(FileHandle);
    ((void**)raw_ptr)[7] = (PVOID)(Flags.AsUlong);
    printf("%08x  %08x\n", liveDumpControl.Flags, liveDumpControl.AddPagesControl);
    for (size_t i = 0; i < sizeof(liveDumpControl); ++i)
    {
        printf("%02X ", pf[i]);
        if ((i + 1) % 0x10 == 0)
        {
            printf("\n");
        }
    }

    printf("\n");
    status = g_NtSystemDebugControl(CONTROL_KERNEL_DUMP,
        (PVOID)(&liveDumpControl),
        sizeof(liveDumpControl),
        NULL,
        0,
        &returnLength);

    if (!NT_SUCCESS(status))
    {
        printf("NtSystemDebugControl failed:  %08x\n", status);
    }

    return status;
}