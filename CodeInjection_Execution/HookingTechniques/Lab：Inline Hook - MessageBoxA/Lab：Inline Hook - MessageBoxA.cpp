#include <iostream>
#include <Windows.h>

// Set up a function to call that will pass execution to our trampoline code
// to ultimately pass execution back to the read MessageBoxA code
typedef int(__stdcall* tdOrigMessageBoxA)(HWND hWnd, LPCSTR lpText, LPCSTR lpCaption, UINT uType);
tdOrigMessageBoxA messageBoxATrampoline;

// This is our function hook
// This is what we will execute before passing execution back to the real function
int WINAPI HookedMessageBox(HWND hWnd, LPCSTR lpText, LPCSTR lpCaption, UINT uType)
{
	// Overwrite the text in the messagebox with our message
	lpText = "Hooked";
	lpCaption = "After Hook";
	// Pass execution to our trampoline which will ultimately return back to the original function
	return messageBoxATrampoline(hWnd, lpText, lpCaption, uType);
}

int Error(const char* msg) {
	printf("%s (%u)", msg, GetLastError());
	return 1;
}

BOOL InstallHook()
{
	BYTE* origFunctionAddress = (BYTE*)GetProcAddress(GetModuleHandleA("user32.dll"), "MessageBoxA");
	if (origFunctionAddress == NULL) {
		Error("Failed to get address of MessageBoxA");
		return FALSE;
	}

	/* Allocate some memory to store the start of the original function */
	BYTE* trampolineAddress = (BYTE*)VirtualAlloc(NULL, 20, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	if (trampolineAddress == NULL) {
		Error("Failed to allocate memory for trampoline");
		return FALSE;
	}

	int numOfBytesToCopy = 5;
	char trampoline[10] = {};

	/* Copy bytes from the original MessageBox function to our trampoline */
	memcpy_s(trampoline, numOfBytesToCopy, origFunctionAddress, 5);

	// The the end of the copied bytes we want to JMP back to the original hooked function
	// 0xE9 is the JMP opcode here. It needs to be given a 4 bytes address
	*(DWORD*)(trampoline + numOfBytesToCopy) = 0xE9;

	/* Calculate where we want to jump back to in the original hooked fuction */
	uintptr_t jumpAddress = (BYTE*)origFunctionAddress - trampolineAddress - numOfBytesToCopy;

	/* Write the JMP address to our trampoline */
	*(uintptr_t*)((uintptr_t)trampoline + numOfBytesToCopy + 1) = jumpAddress;

	/* Write the trampoline to the allocated trampoline memory region */
	if (!WriteProcessMemory(GetCurrentProcess(), trampolineAddress, trampoline, sizeof(trampoline), NULL)) {
		return Error("Error while writing process memory to trampoline");
	}

	/* Change memory protection on messageBox code to make sure it's writable */
	DWORD oldProtectVal;
	VirtualProtect(origFunctionAddress, 6, PAGE_READWRITE, &oldProtectVal);

	/* Patch the original MessageBox code */
	// First we replace the first BYTE with a JMP instruction
	*(BYTE*)origFunctionAddress = 0xE9;

	// Then we calculate the relative address to JMP to our Hook function
	intptr_t hookAddress = (intptr_t)((CHAR*)HookedMessageBox - (intptr_t)origFunctionAddress) - 5;

	// Write the relative address to the original MessageBoxA function
	*(intptr_t*)((intptr_t)origFunctionAddress + 1) = hookAddress;

	// Restore original memory protection on messageBox code
	VirtualProtect(origFunctionAddress, 6, oldProtectVal, &oldProtectVal);

	// Cast the trampoline address to a function 
	messageBoxATrampoline = (tdOrigMessageBoxA)trampolineAddress;

	return TRUE;
}

int main()
{
	BYTE* origFunctionAddress = NULL;
	BYTE* trampolineAddress = NULL;

	// Call MessageBoxA before hooking to show original functionality
	MessageBoxA(NULL, "Hello World!", "Before Hook", MB_OK);

	// Hook the MessageBoxA function
	InstallHook();

	// The hook should now be complete
	// Call message box again to test the hook
	MessageBoxA(NULL, "hi", "hi", MB_OK);

	return 0;
}