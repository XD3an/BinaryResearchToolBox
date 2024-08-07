#include <iostream>
#include <Windows.h>

int main()
{
	MessageBoxW(NULL, L"Hello, World!", L"Before Hook", MB_OK);
	system("pause");
	MessageBoxW(NULL, L"Hello, World!", L"After Hook", MB_OK);
	return 0;
}