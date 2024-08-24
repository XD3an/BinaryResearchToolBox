#include <stdio.h>
#include <windows.h>

#pragma warning(disable : 4996) // ref: https://learn.microsoft.com/zh-tw/cpp/error-messages/compiler-warnings/compiler-warning-level-3-c4996?view=msvc-170

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

void PeParser(char* BinaryData)
{
    IMAGE_DOS_HEADER* DosHeader = (IMAGE_DOS_HEADER*)BinaryData;
    IMAGE_NT_HEADERS* NtHeaders = (IMAGE_NT_HEADERS*)((size_t)DosHeader + DosHeader->e_lfanew);
    IMAGE_SECTION_HEADER* SecHeader = (IMAGE_SECTION_HEADER*)((size_t)NtHeaders + sizeof(*NtHeaders));

    // DOS header
    /*
        - e_magic
        - e_lfanew: The offset of NT Header
        ...
    */
    printf("=============================== DOS Header =================================\n");
    printf("[+] DOS Header->e_magic: %x\n", DosHeader->e_magic);
    printf("[+] DOS Header->e_lfanew: %x\n", DosHeader->e_lfanew);
    if (DosHeader->e_magic != IMAGE_DOS_SIGNATURE || NtHeaders->Signature != IMAGE_NT_SIGNATURE)
    {
        puts("[!] PE binary broken or invalid?");
        return;
    }

    printf("=============================== File header ================================\n");

    // Signature
    if (auto signature = &NtHeaders->Signature)
    {
        printf("[+] Signature: %s\n", signature);
    }

    // File header
    /*
        - *Machine
        - *NumberOfSection
        - TimeDateStamp
        - *PointerOfSymbolTable
        - *NumberOfSymbols
        - *SizeOfOptionalHeader
        - *Characteristics
        ...
    */
    if (auto FileHeader = &NtHeaders->FileHeader)
    {
        printf("[+] File Header->Machine: %d\n", FileHeader->Machine);
        printf("[+] File Header->NumberOfSections: %d\n", FileHeader->NumberOfSections);
        printf("[+] File Header->TimeDateStamp: %d\n", FileHeader->TimeDateStamp);
        printf("[+] File Header->PointerOfSymbolTable: %p\n", FileHeader->PointerToSymbolTable);
        printf("[+] File Header->NumberOfSymbols: %d\n", FileHeader->NumberOfSymbols);
        printf("[+] File Header->SizeOfOptionalHeader: %d\n", FileHeader->SizeOfOptionalHeader);
        printf("[+] File Header->Characteristic: %d\n", FileHeader->Characteristics);
    }

    printf("============================= Optional header ==============================\n");

    // Optional header
    /*
        - *ImageBase
        - SizeOfCode
        - *AddressOfEntryPoint
        - BaseofCode
        - *SizeOfImage
        - *SizeOfHeader
        - *DataDirectory
        ...
    */
    // display information of optional header
    if (auto OptHeader = &NtHeaders->OptionalHeader)
    {
        printf("[+] Optional Header->ImageBase prefer @ %p\n", OptHeader->ImageBase);
        printf("[+] Optional Header->SizeOfCode: %x bytes.\n", OptHeader->SizeOfCode);
        printf("[+] Optional Header->SizeOfImage: %x bytes.\n", OptHeader->SizeOfImage);
        printf("[+] Optional Header->SizeOfHeader: %x bytes.\n", OptHeader->SizeOfHeaders);
        printf("[+] Optional Header->AddressOfEntryPoint: %p\n", OptHeader->AddressOfEntryPoint);
        printf("[+] Optional Header->DataDirectory: %p \n", OptHeader->DataDirectory);
        // ============================================================================================
        printf("[+] Dynamic Memory Usage: %x bytes.\n", OptHeader->SizeOfImage);
        printf("[+] Dynamic EntryPoint @ %p\n", OptHeader->ImageBase + OptHeader->AddressOfEntryPoint);
    }

    printf("============================= Section header ===============================\n");

    // Section header
    /*
        - *Name
        - *PointerToRawData
        - *SizeOfRawData
        - Virtual Address
        - Misc
        - Characteristic
    */
    // enumerate section data
    puts("[+] Section Info");
    for (size_t i = 0; i < NtHeaders->FileHeader.NumberOfSections; i++)
    {
        printf("\t#%.2x - %8s - %.8x - %.8x \n", i, SecHeader[i].Name, SecHeader[i].PointerToRawData, SecHeader[i].SizeOfRawData);
    }
}

int main(int argc, char** argv)
{
    if (argc < 2)
    {
        puts("[!] Usage: .\\PeParser.exe [\\path\\to\\pe]");
        return 1;
    }

    char* binaryData;
    DWORD binarySize;

    if (!ReadBinFile(argv[1], binaryData, binarySize))
    {
        puts("[!] Failed to open PE file!");
        return 0;
    }
    else 
    {
        // PE Parser
        PeParser(binaryData);
    }
    
    return 0;
}