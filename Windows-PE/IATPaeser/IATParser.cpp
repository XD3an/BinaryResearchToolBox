#include <stdio.h>
#include <windows.h>
#pragma warning(disable : 4996)
#define getDosHdr(buf) ((IMAGE_DOS_HEADER *)buf)
#define getNtHdr(buf) ((IMAGE_NT_HEADERS *)((size_t)buf + ((IMAGE_DOS_HEADER *)buf)->e_lfanew))
#define getSectionArr(buf) ((IMAGE_SECTION_HEADER *)((size_t)buf + ((IMAGE_DOS_HEADER *)buf)->e_lfanew + sizeof(IMAGE_NT_HEADERS)))

BOOL ReadBinFile(const char* fileName, char*& buffer, DWORD& size)
{
    // Open file
    FILE* fp = nullptr;
    if (fopen_s(&fp, fileName, "rb"))
    {
        return false;
    }
    else
    {
        // Get the size of the binary file
        fseek(fp, 0, SEEK_END);
        size = ftell(fp);
        fseek(fp, 0, SEEK_SET);

        // Get the content of the binary file
        buffer = new char[size];
        if (buffer == nullptr)
        {
            fclose(fp);
            return false;
        }
        fread(buffer, sizeof(char), size, fp);

        // finalization
        fclose(fp);
        return true;
    }

}

size_t RvaToOffset(char* ExeData, size_t RVA)
{
    for (size_t i = 0; i < getNtHdr(ExeData)->FileHeader.NumberOfSections; i++)
    {
        auto CurrSection = getSectionArr(ExeData)[i];
        if (RVA >= CurrSection.VirtualAddress &&
            RVA <= CurrSection.VirtualAddress + CurrSection.Misc.VirtualSize)
            return CurrSection.PointerToRawData + (RVA - CurrSection.VirtualAddress);
    }
    return 0;
}

void IATParser(char* Buffer, DWORD Size)
{
    // lookup RVA of IAT (Import Address Table)、offset、len
    IMAGE_DATA_DIRECTORY IATDir = getNtHdr(Buffer)->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IAT];
    size_t offset_impAddrArr = RvaToOffset(Buffer, IATDir.VirtualAddress);
    size_t len_iatCallVia = IATDir.Size / sizeof(DWORD);

    // parse table
    auto IATArr = (IMAGE_THUNK_DATA*)(Buffer + offset_impAddrArr);
    for (int i = 0; i < len_iatCallVia; IATArr++, i++)
        if (auto nameRVA = IATArr->u1.Function)
        {
            PIMAGE_IMPORT_BY_NAME k = (PIMAGE_IMPORT_BY_NAME)(Buffer + RvaToOffset(Buffer, nameRVA));
            printf("[+] import Function - %s (hint = %i)\n", &k->Name, k->Hint);
        }
}

int main(int argc, char** argv)
{
    char* Buffer;
    DWORD Size;

    if (argc != 2)
    { 
        puts("[!] Usage: .\\IATParser.exe [path\\to\\exe]");
    }
    else if (ReadBinFile(argv[1], Buffer, Size))
    {
        IATParser(Buffer, Size);
    }
    else
    {
        puts("[!] dll file not found.");
    }
    return 0;
}