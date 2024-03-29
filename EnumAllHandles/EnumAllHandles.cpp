#include "pch.h"
#include <Windows.h>
#include <stdio.h>
#include <iostream>
#include <fstream>

using namespace std;

#define NT_SUCCESS(x) ((x) >= 0)
#define STATUS_INFO_LENGTH_MISMATCH 0xc0000004

#define SystemHandleInformation 16
#define ObjectBasicInformation 0
#define ObjectNameInformation 1
#define ObjectTypeInformation 2


typedef enum _SYSTEM_INFORMATION_CLASS {
	SystemBasicInformation = 0,
	SystemPerformanceInformation = 2,
	SystemTimeOfDayInformation = 3,
	SystemProcessInformation = 5,
	SystemProcessorPerformanceInformation = 8,
	SystemInterruptInformation = 23,
	SystemExceptionInformation = 33,
	SystemRegistryQuotaInformation = 37,
	SystemLookasideInformation = 45
} SYSTEM_INFORMATION_CLASS;

typedef struct _UNICODE_STRING
{
	USHORT Length;
	USHORT MaximumLength;
	PWSTR Buffer;
} UNICODE_STRING, *PUNICODE_STRING;


typedef struct _OBJECT_NAME_INFORMATION
{
	UNICODE_STRING Name;

} OBJECT_NAME_INFORMATION, *POBJECT_NAME_INFORMATION;

typedef NTSTATUS(NTAPI *_NtQuerySystemInformation)(
	ULONG SystemInformationClass,
	PVOID SystemInformation,
	ULONG SystemInformationLength,
	PULONG ReturnLength
	);
typedef NTSTATUS(NTAPI *_NtDuplicateObject)(
	HANDLE SourceProcessHandle,
	HANDLE SourceHandle,
	HANDLE TargetProcessHandle,
	PHANDLE TargetHandle,
	ACCESS_MASK DesiredAccess,
	ULONG Attributes,
	ULONG Options
	);
typedef NTSTATUS(NTAPI *_NtQueryObject)(
	HANDLE ObjectHandle,
	ULONG ObjectInformationClass,
	PVOID ObjectInformation,
	ULONG ObjectInformationLength,
	PULONG ReturnLength
	);

typedef struct _SYSTEM_HANDLE
{
	ULONG ProcessId;
	BYTE ObjectTypeNumber;
	BYTE Flags;
	USHORT Handle;
	PVOID Object;
	ACCESS_MASK GrantedAccess;
} SYSTEM_HANDLE, *PSYSTEM_HANDLE;

typedef struct _SYSTEM_HANDLE_INFORMATION
{
	ULONG HandleCount;
	SYSTEM_HANDLE Handles[1];
} SYSTEM_HANDLE_INFORMATION, *PSYSTEM_HANDLE_INFORMATION;

typedef enum _POOL_TYPE
{
	NonPagedPool,
	PagedPool,
	NonPagedPoolMustSucceed,
	DontUseThisType,
	NonPagedPoolCacheAligned,
	PagedPoolCacheAligned,
	NonPagedPoolCacheAlignedMustS
} POOL_TYPE, *PPOOL_TYPE;

typedef struct _OBJECT_TYPE_INFORMATION
{
	UNICODE_STRING Name;
	ULONG TotalNumberOfObjects;
	ULONG TotalNumberOfHandles;
	ULONG TotalPagedPoolUsage;
	ULONG TotalNonPagedPoolUsage;
	ULONG TotalNamePoolUsage;
	ULONG TotalHandleTableUsage;
	ULONG HighWaterNumberOfObjects;
	ULONG HighWaterNumberOfHandles;
	ULONG HighWaterPagedPoolUsage;
	ULONG HighWaterNonPagedPoolUsage;
	ULONG HighWaterNamePoolUsage;
	ULONG HighWaterHandleTableUsage;
	ULONG InvalidAttributes;
	GENERIC_MAPPING GenericMapping;
	ULONG ValidAccess;
	BOOLEAN SecurityRequired;
	BOOLEAN MaintainHandleCount;
	USHORT MaintainTypeList;
	POOL_TYPE PoolType;
	ULONG PagedPoolUsage;
	ULONG NonPagedPoolUsage;
} OBJECT_TYPE_INFORMATION, *POBJECT_TYPE_INFORMATION;

// Convert Unicode to Printable constant char [String]
const char* ToString(PWSTR pstr, int Length)
{
	int nameLength = Length;
	char *str = new char[nameLength];


	if (nameLength <= 0)
	{
		return (const char*)L"-";

	}
	else {
		for (int a = 0; a < nameLength; a++)
		{
			str[a] = (char)(LPCTSTR)pstr[a];
		}

	}

	return str;
}

// Return the Type of the Handle
const char* GetHandleType(HANDLE Handle)
{
	_NtQueryObject NtQueryObject = (_NtQueryObject)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtQueryObject");

	POBJECT_TYPE_INFORMATION OBJECT_TYPE;
	ULONG GuessSize = 256;
	ULONG RequiredSize = 0;
	NTSTATUS STATUS = 0x0;

	if (Handle == INVALID_HANDLE_VALUE || Handle == NULL)
	{	
		return (const char*)L"-";
	}

	// Allocate Memory
	OBJECT_TYPE = (POBJECT_TYPE_INFORMATION)VirtualAlloc(NULL, (SIZE_T)GuessSize, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);

	if (!OBJECT_TYPE)
	{
		printf("Error allocating : 0x%x", GetLastError());

	}
	// Query Object
	while (NtQueryObject(Handle, ObjectTypeInformation, OBJECT_TYPE, GuessSize, &RequiredSize) == STATUS_INFO_LENGTH_MISMATCH)
	{
		// Free the Memory
		VirtualFree(OBJECT_TYPE, (SIZE_T)GuessSize, MEM_DECOMMIT);
		// Update GuessSize
		GuessSize = RequiredSize;
		// Re-Allocate Memory
		OBJECT_TYPE = (POBJECT_TYPE_INFORMATION)VirtualAlloc(NULL, (SIZE_T)GuessSize, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
	}

	// Print out the Type of Handle Object
	//cout << ToString(OBJECT_TYPE->Name.Buffer ,OBJECT_TYPE->Name.Length) << "\n";

	return ToString(OBJECT_TYPE->Name.Buffer, OBJECT_TYPE->Name.Length);
}


// Return the Name of the Handle and the Handle to the Object
const char* GetHandleName(IN SYSTEM_HANDLE Handle, OUT PHANDLE DUP_HANDLE)
{
	POBJECT_NAME_INFORMATION OBJECT_NAME;
	HANDLE PROCESS_HANDLE;
	ULONG GuessSize = 256;
	ULONG RequiredSize = 0;
	NTSTATUS STATUS = 0x0;
	ofstream ofile;

	// Check if can get a Handle by OpenProcess
	PROCESS_HANDLE = OpenProcess(PROCESS_DUP_HANDLE, FALSE, Handle.ProcessId);

	// Check if Handle is Valid and Opened
	if (PROCESS_HANDLE != INVALID_HANDLE_VALUE && PROCESS_HANDLE != NULL)
	{

		// Try to Duplicate the Target File Handle
		if (GetProcessId(GetCurrentProcess()) != Handle.ProcessId)
		{
			STATUS = DuplicateHandle(PROCESS_HANDLE, (HANDLE)Handle.Handle, GetCurrentProcess(), DUP_HANDLE, STANDARD_RIGHTS_ALL, FALSE, DUPLICATE_SAME_ACCESS);
		}
		else {
			STATUS = DuplicateHandle(GetCurrentProcess(), (HANDLE)Handle.Handle, GetCurrentProcess(), DUP_HANDLE, STANDARD_RIGHTS_ALL, FALSE, DUPLICATE_SAME_ACCESS);
			if (STATUS == 0x1)
			{
				Sleep(10);
			}
		}

		if (STATUS != STATUS_INVALID_HANDLE)
		{
			// Check if the Duplicated Handle is Valid and Opened
			if (*DUP_HANDLE != INVALID_HANDLE_VALUE && *DUP_HANDLE != NULL)
			{

				// Check the Initial Size
				cout << "\nInitial Query Size: " << GuessSize;

				// Allocate Memory
				OBJECT_NAME = (POBJECT_NAME_INFORMATION)VirtualAlloc(NULL, (SIZE_T)GuessSize, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);


				_NtQueryObject NtQueryObject = (_NtQueryObject)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtQueryObject");

				// Query Object
				while (NtQueryObject(*DUP_HANDLE, ObjectNameInformation, OBJECT_NAME, GuessSize, &RequiredSize) == STATUS_INFO_LENGTH_MISMATCH)
				{

					// Free the Memory
					VirtualFree(OBJECT_NAME, (SIZE_T)GuessSize, MEM_DECOMMIT);

					// Update the Guess Size
					GuessSize = RequiredSize;

					// Re-Allocate Memory Space
					OBJECT_NAME = (POBJECT_NAME_INFORMATION)VirtualAlloc(NULL, (SIZE_T)GuessSize, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);

				}

				return ToString(OBJECT_NAME->Name.Buffer, OBJECT_NAME->Name.Length);
			}

		}
		else {
			CloseHandle(PROCESS_HANDLE);
			CloseHandle(*DUP_HANDLE);
			return (const char*)L"-";
		}

		CloseHandle(PROCESS_HANDLE);
		CloseHandle(*DUP_HANDLE);
	}
	else {
		return (const char*)L"-";
		// cout << "Failed to Duplicate : " << (PVOID)Handle.Handle << " With Access Mask of : " <<(PVOID)Handle.GrantedAccess << " Process ID : " << Handle.ProcessId << "\n";
	}

}

void __stdcall GetSystemHandleInformation(const char* Path)
{

	// Declaration and Initialization of Variables
	PSYSTEM_HANDLE_INFORMATION HandleInformation = NULL;
	ULONG GuessSize = 1024;
	ULONG RequiredSize = 0;

	// Check Guess Size
	cout << "\nInitial Size : " << GuessSize;

	// Allocate Memory
	HandleInformation = (PSYSTEM_HANDLE_INFORMATION)VirtualAlloc(NULL,
		(SIZE_T)GuessSize,
		MEM_RESERVE | MEM_COMMIT,
		PAGE_READWRITE);

	_NtQuerySystemInformation NtQuerySystemInformation = (_NtQuerySystemInformation)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtQuerySystemInformation");
	// Loop until the Function Succeeds
	while (NtQuerySystemInformation(SystemHandleInformation, HandleInformation, GuessSize, &RequiredSize) == STATUS_INFO_LENGTH_MISMATCH)
	{
		// Free First the Memory
		VirtualFree(HandleInformation,
			(SIZE_T)GuessSize,
			MEM_DECOMMIT);

		// Update the Guess Size
		GuessSize = RequiredSize;

		// Allocate Memory Again - Resize
		HandleInformation = (PSYSTEM_HANDLE_INFORMATION)VirtualAlloc(NULL,
			(SIZE_T)GuessSize,
			MEM_RESERVE | MEM_COMMIT,
			PAGE_READWRITE);

	}

	// Check the New Size
	cout << "\nNew Size : " << GuessSize;

	// Write All Handles in the File
	ofstream ofile;
	ofile.open(Path, std::ios_base::trunc);

	ofile << "Process ID \t\tHandle\t\t\t\tType\t\t\t\t\t\tAddress\t\t\t\tGranted Access\t\t\tName\t\t\tFlags\t\n";

	for (DWORD a = 0; a < HandleInformation->HandleCount; a++)
	{
		// Hold the Current Index Handle
		SYSTEM_HANDLE Handle = HandleInformation->Handles[a];
		HANDLE OBJECT_HANDLE = NULL;
		const char* Name = GetHandleName(Handle, &OBJECT_HANDLE);
		const char* Type = GetHandleType(OBJECT_HANDLE);

		// Output to the File the current Handle Information
		ofile << Handle.ProcessId << "\t\t\t" << (PVOID)Handle.Handle << "\t\t" << Type << "\t\t\t\t\t\t"
			<< (PVOID)Handle.Object << "\t\t" << (PVOID)Handle.GrantedAccess << "\t\t"
			<< Name << "\t\t\t" << (PVOID)Handle.Flags << "\n";

	}

	ofile.close();
}

int main(int argc, char *argv[])
{
	cout << "List of all the handles in the computer\n";
	if (argc != 2)
	{
		cout << "Usage: " << argv[0] << " <PathToSave>\n";
		return 1;
	}


	GetSystemHandleInformation(argv[1]);
	cout << "Listed all handles successfully\n";
	return 0;
}