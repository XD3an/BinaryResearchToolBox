#include <iostream>
#include <Windows.h>
#include <tlhelp32.h>

VOID EnumRunProc()
{
    PROCESSENTRY32W procEntry = { 0 };
    procEntry.dwSize = sizeof(PROCESSENTRY32W);
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

    if (hSnapshot != INVALID_HANDLE_VALUE) {
        if (Process32FirstW(hSnapshot, &procEntry)) {
            do {
                std::wstring procName = procEntry.szExeFile;
                std::wcout << "[*] " << procName << std::endl;
            } while (Process32NextW(hSnapshot, &procEntry));
        }
        CloseHandle(hSnapshot);
    }
    else {
        std::wcerr << L"Failed to create process snapshot." << std::endl;
    }

}

int main()
{
    EnumRunProc();
    return EXIT_SUCCESS;
}
