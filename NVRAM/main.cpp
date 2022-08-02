#include <stdio.h>
#include <iostream>
#include "Windows.h"
#include "subauth.h"
#include <system_error>
#include <sstream>
#include <iostream>
#include <iomanip>
#include <iostream>     // std::cout, std::endl
#include <iomanip>      // std::setw
#include <stdio.h>

// Last privilege
#define SE_CREATE_SYMBOLIC_LINK		35

typedef NTSTATUS(WINAPI* RTLADJUSTPRIVILEGE)(
	_In_  ULONG    Privilege,
	_In_  BOOLEAN  Enable,
	_In_  BOOLEAN  CurrentThread,
	_Out_ PBOOLEAN Enabled);


unsigned int a2v(char c)
{
	if ((c >= '0') && (c <= '9'))
	{
		return (unsigned int) c - '0';
	}
	if ((c >= 'a') && (c <= 'f'))
	{
		return (unsigned int)c - 'a' + 10;
	}
	else
	{
		printf("converted non hex values\n");
		return 0;
	}
}

char v2a(unsigned int c)
{
	const char hex[] = "0123456789abcdef";
	if (c > sizeof(hex))
	{
		printf("Failed to convert non-hex value, returned '0'\n");
		return '0';
	}
	return hex[c];
}

char* unhexlify(char* hstr, size_t* size)
{
	if (strlen(hstr) % 2 != 0)
	{
		printf("uneven hex bytes\n");
	}

	*size = (strlen(hstr) / 2) + 1;
	char* bstr = (char*)malloc(*size);
	char* pbstr = bstr;
	if (NULL == bstr) 
	{
		printf("Failed to allocate memory\n");
		return NULL;
	}
	for (size_t i = 0; i < strlen(hstr); i += 2)
	{
		char c = (char) (a2v(hstr[i]) << 4) + a2v(hstr[i + 1]);
		if (c == 0) {
			*pbstr++ = -128;
		}
		else {
			*pbstr++ = c;
		}
	}
	*pbstr++ = '\0';
	return bstr;
}

char* hexlify(char* bstr)
{
	char* hstr = (char*)malloc((strlen(bstr) * 2) + 1);
	char* phstr = hstr;

	if (NULL == hstr)
	{
		printf("Failed to allocate memory\n");
		return NULL;
	}
	for (size_t i = 0; i < strlen(bstr); i++)
	{
		if (bstr[i] == -128)
		{
			*phstr++ = '0';
			*phstr++ = '0';
		}
		else {
			*phstr++ = v2a((bstr[i] >> 4) & 0x0F);
			*phstr++ = v2a((bstr[i]) & 0x0F);
		}
	}
	*phstr++ = '\0';
	return hstr;
}

HMODULE hNtdll = NULL;


// Taken from https://github.com/gentilkiwi/mimikatz/blob/e10bde5b16b747dc09ca5146f93f2beaf74dd17a/mimikatz/modules/kuhl_m_privilege.c
NTSTATUS kuhl_m_privilege_simple(ULONG privId)
{
	typedef NTSTATUS(NTAPI* TFNRtlAdjustPrivilege)(ULONG, BOOLEAN, BOOLEAN, PBOOLEAN);
	TFNRtlAdjustPrivilege pfnRtlAdjustPrivilege = NULL;
	hNtdll = GetModuleHandleA("ntdll.dll");
	if (NULL == hNtdll)
	{
		printf("failed to module handle ntdll\n exiting program\n");
		return -2;
	}
	pfnRtlAdjustPrivilege = (TFNRtlAdjustPrivilege)GetProcAddress(hNtdll, "RtlAdjustPrivilege");
	if (NULL == pfnRtlAdjustPrivilege)
	{
		printf("Failed to get the address of one of the functions\n");
		return -2;
	}

	BOOLEAN previousState;
	NTSTATUS status = pfnRtlAdjustPrivilege(privId, TRUE, FALSE, &previousState);
	if (status != STATUS_SUCCESS)
	{
		printf("Failed to adjust privileges\n");
	}

	return status;
}

// Caveat #1: Check if system supports UEFI.
int IsFeatureSupported()
{
	int buffer;
	GetFirmwareEnvironmentVariable(L"", L"{00000000-0000-0000-0000-000000000000}", &buffer, sizeof(buffer));
	return (GetLastError() == ERROR_INVALID_FUNCTION) ? 0 : 1;
}

// Caveat #2: SeSystemEnvironmentPrivilege needs to be set.
int SetSystemEnvironmentPrivilege()
{
	HMODULE hnd_module = LoadLibrary(L"ntdll.dll");
	RTLADJUSTPRIVILEGE RtlAdjustPrivilege = (RTLADJUSTPRIVILEGE)GetProcAddress(hnd_module, "RtlAdjustPrivilege");
	ULONG SeSystemEnvironmentPrivilege = 22;
	BOOLEAN enabled = false;
	RtlAdjustPrivilege(SeSystemEnvironmentPrivilege, true, false, &enabled);
	return (int)enabled;
}

int SetGetNVRAM(int argc, char* argv[])
{
	wprintf(L"Get/Set NVRAM Variables in UEFI\n\n");
	if (argc < 4)
	{
		wprintf(L"format: nvram.exe <W/R> <GUID> <key> [value in hex]\n\n");
		return -1;
	}
	
	if (!IsFeatureSupported())
	{
		printf("ERROR: This feature is not supported on your host. it is required to run from a machine with UEFI\n");
		return -1;
	}

	SetSystemEnvironmentPrivilege();
	wchar_t variable_name[30] = { 0 };
	wchar_t guid[40] = { 0 };
	size_t outSize = 0;
	NTSTATUS s = 0;
	char* get_buffer = (char*)calloc(500, sizeof(wchar_t));

	if (NULL == get_buffer) 
	{
		printf("Failed to allocate memory\n");
		return -1;
	}

	mbstowcs_s(&outSize, variable_name, argv[3], strlen(argv[3]));
	mbstowcs_s(&outSize, guid, argv[2], strlen(argv[2]));
	printf("[before syscall]\n");
	if (strcmp(argv[1], "W") == 0 || strcmp(argv[1], "w") == 0)
	{
		size_t size_new_buff = 0;
		char* new_buff = unhexlify(argv[4], &size_new_buff);
		printf("\n");
		for (size_t i = 0; i < size_new_buff; ++i)
		{
			printf("%02X ", new_buff[i] & 0xff);
			if ((i + 1) % 0x10 == 0)
			{
				printf("\n");
			}
		}

		printf("\n");
		// Equivalent to: s = SetFirmwareEnvironmentVariableEx(variable_name, guid, new_buff, size_new_buff, 0x00000001);
		s = SetFirmwareEnvironmentVariable(variable_name, guid, new_buff, ((DWORD) size_new_buff));
		//If the function SetFirmwareEnvironmentVariable succeeds, the return value is a nonzero value.
		wprintf(L"[SET] %s status %x (non zero required)\n", variable_name, (unsigned int) s); 
	}

	s = (DWORD) GetFirmwareEnvironmentVariable(variable_name, guid, get_buffer, 500);
	// The return value is the number of bytes stored in the pBuffer buffer.
	wprintf(L"[GET] %s bytes read: 0x%x\n", variable_name, (unsigned int)s);
	printf("\n");
	for (size_t i = 0; i < s; ++i)
	{
		printf("%02X ", get_buffer[i] & 0xff);
		if ((i + 1) % 0x10 == 0)
		{
			printf("\n");
		}
	}

	printf("\n[After syscall]\n");
	return 0;
}

int main(int argc, char* argv[])
{
	int ret_val = 0;

	printf("Permissions enabled:");
	// Execute the loop twice because on the second iteration it is possible to gain more privileges after we gained some on the first iteration such as TCB. 
	for (int t = 0; t < 2; t++) {
		for (unsigned int i = 0; i <= SE_CREATE_SYMBOLIC_LINK; i++)
		{
			int ntRetValStatus = kuhl_m_privilege_simple(i);
			if (NT_SUCCESS(ntRetValStatus))
			{
				printf("%d ", i);
			}
		}
	}

	printf("\n");
	ret_val = SetGetNVRAM(argc, argv);
	if (0 == ret_val)
	{
		printf("SUCCESS %d \n", ret_val);
	}
	else
	{
		printf("FAILED %d \n", ret_val);
	}

	return ret_val;
}