#include <stdio.h>
#include <windows.h>
#pragma warning(disable : 4996)
#define getNtHdr(buf) ((IMAGE_NT_HEADERS *)((size_t)buf + ((IMAGE_DOS_HEADER *)buf)->e_lfanew))
#define getSectionArr(buf) ((IMAGE_SECTION_HEADER *)((size_t)buf + ((IMAGE_DOS_HEADER *)buf)->e_lfanew + sizeof(IMAGE_NT_HEADERS)))

size_t ptr_msgboxa = 0;

/* Hook function (Hook `MessageBoxA()`) */
void (*ptr)(UINT, LPCSTR, LPCSTR, UINT) = [](UINT hwnd, LPCSTR lpText, LPCSTR lpTitle, UINT uType)
{
    printf("[Hook] MessageBoxA(%i, \"%s\", \"%s\", %i)", hwnd, lpText, lpTitle, uType);
    ((UINT(*)(UINT, LPCSTR, LPCSTR, UINT))ptr_msgboxa)(hwnd, "MessageBoxA got hooked", "alert", uType);
};

void IATHook(char* module, const char* szHook_ApiName, size_t callback, size_t& ApiAddr)
{
    /* get Import directory */
    auto IDir = getNtHdr(module)->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    /* get import module list */
    auto impModuleList = (IMAGE_IMPORT_DESCRIPTOR*)&module[IDir.VirtualAddress];

    /* iterate through import module list */
    for (; impModuleList->Name; impModuleList++)
    {
        auto callViaArr = (IMAGE_THUNK_DATA*)&module[impModuleList->FirstThunk];            // get call via array
        auto ApiNamesArr = (IMAGE_THUNK_DATA*)&module[impModuleList->OriginalFirstThunk];   // get api names array
        // iterate through api names array
        for (int i = 0; ApiNamesArr[i].u1.Function; i++)
        {
            auto curr_impApi = (PIMAGE_IMPORT_BY_NAME)&module[ApiNamesArr[i].u1.Function];
            // check if current api name matches the one we're looking for 
            // if so, replace the address in call via array with our callback
            if (!strcmp(szHook_ApiName, (char*)curr_impApi->Name))
            {
                // Hook
                DWORD oldProtect;
                VirtualProtect(&callViaArr[i], sizeof(size_t), PAGE_EXECUTE_READWRITE, &oldProtect);
                ApiAddr = callViaArr[i].u1.Function;
                callViaArr[i].u1.Function = callback;
                VirtualProtect(&callViaArr[i], sizeof(size_t), oldProtect, &oldProtect);
                break;
            }
        }
    }
}

int main(int argc, char** argv)
{
    // try to call original function
    printf("[*] MessageBoxA@%p\n", MessageBoxA);
    MessageBoxA(0, "Hello World!", "Before Hook", 0);

    // hook MessageBoxA
    IATHook((char*)GetModuleHandle(NULL), "MessageBoxA", (size_t)ptr, ptr_msgboxa);

    // try to call hooked function
    printf("[*] MessageBoxA@%p\n", MessageBoxA);
    MessageBoxA(0, "Hello World!", "After Hook", 0);
    return 0;
}