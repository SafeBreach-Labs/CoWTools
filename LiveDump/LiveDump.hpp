#pragma once
// Based on the code: https://code.google.com/archive/p/livedump/

#include <stdio.h>
#include <windows.h>
#include <winternl.h>
#include <assert.h>
#include <TlHelp32.h>

#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)
#define CONTROL_TRIAGE_DUMP 29
#define CONTROL_KERNEL_DUMP 37
#define TRIAGE_SIZE 0x20000 // must be >132k and <1MB
#define MAX_TRIAGE_THREADS 16

#pragma comment(lib, "ntdll")

//
// From NDK, argument required for parameter 29.
//
typedef struct _SYSDBG_TRIAGE_DUMP
{
    ULONG Flags;
    ULONG BugCheckCode;
    ULONG_PTR BugCheckParam1;
    ULONG_PTR BugCheckParam2;
    ULONG_PTR BugCheckParam3;
    ULONG_PTR BugCheckParam4;
    ULONG ProcessHandles;
    ULONG ThreadHandles;
    PHANDLE Handles;
} SYSDBG_TRIAGE_DUMP, * PSYSDBG_TRIAGE_DUMP;

//
// Undocumented.  Structures relevant for new parameter 37.
// Greetz to Alex I.
//
typedef union _SYSDBG_LIVEDUMP_CONTROL_FLAGS
{
    struct
    {
        ULONG UseDumpStorageStack : 1;
        ULONG CompressMemoryPagesData : 1;
        ULONG IncludeUserSpaceMemoryPages : 1;
        ULONG Reserved : 29;
    };
    ULONG AsUlong;
} SYSDBG_LIVEDUMP_CONTROL_FLAGS;


typedef union _SYSDBG_LIVEDUMP_CONTROL_ADDPAGES
{
    struct
    {
        ULONG HypervisorPages : 1;
        ULONG Reserved : 31;
    };
    ULONG AsUlong;
} SYSDBG_LIVEDUMP_CONTROL_ADDPAGES;

typedef struct _SYSDBG_LIVEDUMP_CONTROL
{
    ULONG Version;
    ULONG BugCheckCode;
    ULONG BugCheckParam1;
    ULONG BugCheckParam2;
    ULONG BugCheckParam3;
    ULONG BugCheckParam4;
    PVOID DumpFileHandle;
    PVOID CancelEventHandle;
    SYSDBG_LIVEDUMP_CONTROL_FLAGS Flags;
    SYSDBG_LIVEDUMP_CONTROL_ADDPAGES AddPagesControl;
    // Not sure why it is required to add the padding but it doesn't work without it.
    void* emptyPlaceHolder;  
    INT emptyPlaceHolder_int;
    INT emptyPlaceHolder_int_2;
} SYSDBG_LIVEDUMP_CONTROL, * PSYSDBG_LIVEDUMP_CONTROL;

typedef
NTSTATUS
(__stdcall*
    NtSystemDebugControl) (
        ULONG ControlCode,
        PVOID InputBuffer,
        ULONG InputBufferLength,
        PVOID OutputBuffer,
        ULONG OutputBufferLength,
        PULONG ReturnLength
        );

BOOL
EnablePrivilege(
    __in PCWSTR PrivilegeName,
    __in BOOLEAN Acquire
);

NTSTATUS
CreateTriageDump(
    __in HANDLE FileHandle,
    __in ULONG Pid
);

NTSTATUS
CreateKernelDump(
    __in HANDLE FileHandle,
    __in SYSDBG_LIVEDUMP_CONTROL_FLAGS Flags,
    __in SYSDBG_LIVEDUMP_CONTROL_ADDPAGES Pages
);

INT
wmain(
    __in INT Argc,
    __in PWCHAR Argv[]
);