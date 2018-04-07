#include <Windows.h>
#include "ADE32.h"
#include "Detour.h"
#include "CDetour.h"

typedef int(WINAPI*_MessageBoxA)(HWND hWnd,LPCSTR lpText,LPCSTR lpCaption,UINT uType);

int WINAPI HookMessageBoxA(HWND hWnd,LPCSTR lpText,LPCSTR lpCaption,UINT uType)
{
	OutputDebugStringA(lpText);
	OutputDebugStringA(lpCaption);
	return 0;
}

void ADE32_Test();
void Detour_Test();
void CDetourTest();


int main(int agrc,char** agrv)
{
	// 目的:让dll加载进来
	HWND hWnd = GetDesktopWindow(); 
	HMODULE hModule = GetModuleHandle(L"user32.dll");

	ADE32_Test();

	Detour_Test();

	CDetourTest();

	return 0;
}

void ADE32_Test()
{
	disasm_struct disam ={0};
	int nDisasm = disasm((BYTE*)MessageBoxA,&disam);
	int nLen = oplen((BYTE*)MessageBoxA);
}

void Detour_Test()
{
	Detour_c detor((DWORD)MessageBoxA,(DWORD)HookMessageBoxA);
	detor.SetupDetour();
	MessageBoxA(NULL,"111","Tip",MB_OK);
	detor.RemoveDetour();
	MessageBoxA(NULL,"222","Tip",MB_OK);
}

void CDetourTest()
{
	CDetour detour;
	void* pJmp = detour.Create("user32.dll","MessageBoxA",(BYTE*)HookMessageBoxA,DETOUR_TYPE_JMP);
	MessageBoxA(NULL,"111","Tip",MB_OK);
	detour.Remove("user32.dll","MessageBoxA",(BYTE*)pJmp,DETOUR_TYPE_JMP);
	MessageBoxA(NULL,"333","Tip",MB_OK);
	free(pJmp);
}
