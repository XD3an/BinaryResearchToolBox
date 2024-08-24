/*
	Release, x86
*/
#include <iostream>
#include <Windows.h>
#pragma comment(linker, "/SUBSYSTEM:Windows /ENTRY:mainCRTStartup")


#pragma optimize("", off)

/* (API) Something we actually want to do... */
void MsgBox(void* address, HWND hWnd, LPCSTR lpText, LPCSTR lpCaption, UINT uType)
{
	int arr[1] = {};
	// Swap `return address` and `address` in the stack
	arr[4] = arr[3] ^ arr[4];
	arr[3] = arr[3] ^ arr[4];
	arr[4] = arr[3] ^ arr[4];
}


/* 
	Calling Method 1: 
	
	Solution: push something to stack for alignment, and the size is how many parameters the API need.

*/ 
void CallingMethod1()
{
	/*
	_asm push esp
	_asm push esp
	_asm push esp
	_asm push esp
	_asm push esp
	*/
	int padding[5] = { 0 };

	// call
	MsgBox(MessageBoxA, NULL, "No Call API??", "Info", MB_OK);
}

/* 
	Calling Method 2: 
	
	Solution: Don't need to care about data alignment problem through change the calling convention to `stdcall` from `cdecl`
*/ 
void CallingMethod2()
{
	typedef int* (_stdcall* _hMessageBoxA)(void* address, HWND hWnd, LPCSTR lpText, LPCSTR lpCaption, UINT uType);
	((_hMessageBoxA)MsgBox)(MessageBoxA, NULL, "No Call API??", "Info", MB_OK);
}

int main()
{
	//MsgBox(MessageBoxA, NULL, "No Call API??", "Info", MB_OK);  // => DATA ALIGNMENT PROBLEM!! 

	/* Calling Method 1 */
	//CallingMethod1();
	
	/* Calling Method 2 */
	CallingMethod2();

	// ...
	MessageBoxA(NULL, "Back to main Continue to run", "Info", MB_OK);
}
#pragma optimize("", on)
