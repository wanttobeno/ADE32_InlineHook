#include<windows.h>
#include"Detour.h"
#include "ADE32.h"

Detour_c::Detour_c(DWORD cdwOldAddress, DWORD cdwMyAddress)
{
	dwNewAddress = 0;
	OpcodeLen = 0;
	dwOldAddress = cdwOldAddress;
	dwMyAddress = cdwMyAddress;
}

Detour_c::~Detour_c()
{
	VirtualFree((PVOID)dwNewAddress, OpcodeLen + 5, MEM_FREE | MEM_RELEASE);
}

DWORD Detour_c::SetupDetour(void)
{
	BYTE* CurrOpcode = (BYTE*)dwOldAddress;
	OpcodeLen = oplen(CurrOpcode);
	CurrOpcode += OpcodeLen;
	while(OpcodeLen < 5)
	{
		int Len = oplen(CurrOpcode);
		if(!Len)
			return 0;

		OpcodeLen += Len;
		CurrOpcode += Len;
	}

	if(VirtualProtect((PVOID)dwOldAddress, OpcodeLen, PAGE_EXECUTE_READWRITE, &dwTempProtect[0]) == FALSE)
		return 0;

	RtlCopyMemory((PVOID)PatchBackup, (PVOID)dwOldAddress, OpcodeLen);

	*(BYTE*) (dwOldAddress + 0) = 0xE9;
	*(DWORD*)(dwOldAddress + 1) = dwMyAddress - dwOldAddress - 5;

	for(int i=5; i < OpcodeLen; i++)
		*(BYTE*) (dwOldAddress + i) = 0x90;		// NOP;

	if(VirtualProtect((PVOID)dwOldAddress, OpcodeLen, dwTempProtect[0], &dwTempProtect[1]) == FALSE)
		return 0;

	dwNewAddress = (DWORD)VirtualAlloc(NULL, OpcodeLen + 6, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	if(dwNewAddress == NULL)
		return 0;

	RtlCopyMemory((PVOID)dwNewAddress, (PVOID)PatchBackup, OpcodeLen);
	*(BYTE*) (dwNewAddress + OpcodeLen + 0) = 0xE9;
	*(DWORD*)(dwNewAddress + OpcodeLen + 1) = (dwOldAddress +  OpcodeLen) - (dwNewAddress + OpcodeLen + 5);

	return dwNewAddress;
}

BOOLEAN Detour_c::RemoveDetour(void)
{
	if(VirtualProtect((PVOID)dwOldAddress, OpcodeLen, PAGE_EXECUTE_READWRITE, &dwTempProtect[0]) == FALSE)
		return FALSE;

	RtlCopyMemory((PVOID)dwOldAddress, (PVOID)PatchBackup, OpcodeLen);

	if(VirtualProtect((PVOID)dwOldAddress, OpcodeLen, dwTempProtect[0], &dwTempProtect[1]) == FALSE)
		return FALSE;

	return TRUE;
}

BOOLEAN Detour_c::RemakeDetour(void)
{
	return FALSE;
}