#include <windows.h>
#include <winternl.h>

bool IsBeingDebugged()
{
#ifdef _WIN64
	PPEB pPeb = (PPEB)__readgsqword(0x60);
#else
	PPEB32 pPeb = (PPEB32)__readfsdword(0x30);
#endif 
	return pPeb->BeingDebugged == 1;
}

int main()
{
	if (IsBeingDebugged())
	{
		MessageBoxA(NULL, "Debugger Detected", "info", MB_OK);
		ExitProcess(-1);
	}
	else
		MessageBoxA(NULL, "Debugger Not Detected", "info", MB_OK);

	return 0;
}