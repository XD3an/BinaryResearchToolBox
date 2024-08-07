#include <iostream>
#include <windows.h>
#include <winnt.h>
#include "pe_struct.h"
#include "infomsg.h"

#pragma warning(disable : 4996) 

int main(int argc, char** argv)
{
    if (argc < 2)
    {
        fail("Usage: %s <PE File>", argv[0]);
        return 1;
    }
    //const char* filename = ".\\x64\\Debug\\PE_Parser.exe";
    const char* filename = argv[1];
    info("File: %s", filename);
    // make sure the file exists
    if (GetFileAttributesA(filename) == INVALID_FILE_ATTRIBUTES)
    {
        fail("File does not exist");
        return 1;
    }

    char* rawData;
    DWORD dRawDataSize;
    MAP_FILE_STRUCT *mapFile = { 0 };

    if (!ReadPEFile(filename, mapFile))
    {
        puts("[!] Failed to open PE file!");
        return 0;
    }
    else
    {
        okay("PE file opened successfully!");
        
        if (!IsPEFile(mapFile->rawData))
        {
			puts("[!] Not a PE file!");
			return 0;
		}
        okay("PE file detected!");
        PEHdrParser(mapFile->rawData);
    }

    return 0;
}

BOOL ReadPEFile(const char* fileName, MAP_FILE_STRUCT*& mapFile)
{
    char *rawData;
    DWORD size;
    FILE* fp = nullptr;

    // Open file
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
        rawData = new char[size];
        if (rawData == nullptr)
        {
            fclose(fp);
            return false;
        }
        fread(rawData, sizeof(char), size, fp);

        // Create a new map file struct
         mapFile = new MAP_FILE_STRUCT;
         if (mapFile == nullptr)
         {
			 fclose(fp);
			 return false;
		 }
         mapFile->rawData = rawData;
		 mapFile->dRawDataSize = size;

        // finalization
        fclose(fp);
        return TRUE;
    }

}

BOOL IsPEFile(char*& rawData)
{
	IMAGE_DOS_HEADER* DosHeader = (IMAGE_DOS_HEADER*)rawData;
	IMAGE_NT_HEADERS* NtHeaders = (IMAGE_NT_HEADERS*)((size_t)DosHeader + DosHeader->e_lfanew);

    if (DosHeader->e_magic != IMAGE_DOS_SIGNATURE || NtHeaders->Signature != IMAGE_NT_SIGNATURE)
    {
		return false;
	}
	return true;
}

IMAGE_DOS_HEADER* GetDosHeader(char*& buffer)
{
	return (IMAGE_DOS_HEADER*)buffer;
}

IMAGE_NT_HEADERS* GetNtHeaders(char*& buffer)
{
	IMAGE_DOS_HEADER* DosHeader = (IMAGE_DOS_HEADER*)buffer;
	return (IMAGE_NT_HEADERS*)((size_t)DosHeader + DosHeader->e_lfanew);
}

IMAGE_SECTION_HEADER* GetSectionHeader(char*& buffer)
{
	IMAGE_DOS_HEADER* DosHeader = (IMAGE_DOS_HEADER*)buffer;
	IMAGE_NT_HEADERS* NtHeaders = (IMAGE_NT_HEADERS*)((size_t)DosHeader + DosHeader->e_lfanew);
	IMAGE_SECTION_HEADER* SecHeader = (IMAGE_SECTION_HEADER*)((size_t)NtHeaders + sizeof(*NtHeaders));
	return SecHeader;
}

size_t RvaToOffset(char* ExeData, size_t RVA)
{
    for (size_t i = 0; i < GetNtHeaders(ExeData)->FileHeader.NumberOfSections; i++)
    {
        auto CurrSection = GetSectionHeader(ExeData)[i];
        if (RVA >= CurrSection.VirtualAddress &&
            RVA <= CurrSection.VirtualAddress + CurrSection.Misc.VirtualSize)
            return CurrSection.PointerToRawData + (RVA - CurrSection.VirtualAddress);
    }
    return 0;
}

void IATParser(char* rawData, DWORD Size)
{
    // lookup RVA of IAT (Import Address Table)、offset、len
    IMAGE_DATA_DIRECTORY IATDir = GetNtHeaders(rawData)->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IAT];
    size_t offset_impAddrArr = RvaToOffset(rawData, IATDir.VirtualAddress);
    size_t len_iatCallVia = IATDir.Size / sizeof(DWORD);

    // parse table
    auto IATArr = (IMAGE_THUNK_DATA*)(rawData + offset_impAddrArr);
    for (int i = 0; i < len_iatCallVia; IATArr++, i++)
        if (auto nameRVA = IATArr->u1.Function)
        {
            PIMAGE_IMPORT_BY_NAME k = (PIMAGE_IMPORT_BY_NAME)(rawData + RvaToOffset(rawData, nameRVA));
            printf("[+] Import Function - %s (hint = %i)\n", &k->Name, k->Hint);
        }
}

void PEHdrParser(char* rawData)
{
    IMAGE_DOS_HEADER* DosHeader = GetDosHeader(rawData);
    IMAGE_NT_HEADERS* NtHeaders = GetNtHeaders(rawData);
    IMAGE_SECTION_HEADER* SecHeader = GetSectionHeader(rawData);

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
        // DataDirectory
        /*
            - VirtualAddress
        	- Size
        
            Offset (PE/PE32+)	Description
                96/112	Export table address and size
                104/120	Import table address and size
                112/128	Resource table address and size
                120/136	Exception table address and size
                128/144	Certificate table address and size
                136/152	Base relocation table address and size
                144/160	Debugging information starting address and size
                152/168	Architecture-specific data address and size
                160/176	Global pointer register relative virtual address
                168/184	Thread local storage (TLS) table address and size
                176/192	Load configuration table address and size
                184/200	Bound import table address and size
                192/208	Import address table address and size
                200/216	Delay import descriptor address and size
                208/224	The CLR header address and size
                216/232	Reserved
        
        */
        for (size_t i = 0; i < IMAGE_NUMBEROF_DIRECTORY_ENTRIES; i++)
        {
            // 
			printf("\t#%.2x - VirtualAddress: %p - Size: %x\n", i, OptHeader->DataDirectory[i].VirtualAddress, OptHeader->DataDirectory[i].Size);
		}

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

    printf("============================= Import Directory  ==========================\n");
    // Import Directory
    /*
      * ImportLookupTable
      * TimeDateStamp
      * ForwarderChain
      * Name
      * ImportAddressTable
    */
    auto ImportDir = (IMAGE_IMPORT_DESCRIPTOR*)(rawData + RvaToOffset(rawData, NtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress));
    for (size_t i = 0; ImportDir[i].Characteristics; i++)
    {
        info("Import Directory #%d", i);
		printf("\tImport Directory->OriginalFirstThunk (Import Name Table): %x\n", ImportDir[i].Characteristics);
		printf("\tImport Directory->TimeDateStamp: %x\n", ImportDir[i].TimeDateStamp);
		printf("\tImport Directory->ForwarderChain: %x\n", ImportDir[i].ForwarderChain);
		printf("\tImport Directory->Name: \"%s\"\n", rawData + RvaToOffset(rawData, ImportDir[i].Name));
		printf("\tImport Directory->FirstThunk (ImportAddressTable): %x\n", ImportDir[i].FirstThunk);
	}

    // IAT (Import Address Table)
    IATParser(rawData, NtHeaders->OptionalHeader.SizeOfImage);

    printf("============================= Export Directory =============================\n");
    
    // Export Directory
    /*
    * ExportFlags
    * TimeDateStamp
    * MajorVersion
    * MinorVersion
    * Name
    * Base
    * NumberOfFunctions
    * NumberOfNames
    * AddressOfFunctions
    * AddressOfNames
    * AddressOfNameOrdinals
    */
    auto ExportDir = (IMAGE_EXPORT_DIRECTORY*)(rawData + RvaToOffset(rawData, NtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress));
    printf("[+] Export Directory->ExportFlags: %x\n", ExportDir->Characteristics);
    printf("[+] Export Directory->TimeDateStamp: %x\n", ExportDir->TimeDateStamp);
    printf("[+] Export Directory->MajorVersion: %x\n", ExportDir->MajorVersion);
    printf("[+] Export Directory->MinorVersion: %x\n", ExportDir->MinorVersion);
    printf("[+] Export Directory->Name: %s\n", rawData + RvaToOffset(rawData, ExportDir->Name));
    printf("[+] Export Directory->Base: %x\n", ExportDir->Base);
    printf("[+] Export Directory->NumberOfFunctions: %x\n", ExportDir->NumberOfFunctions);
    printf("[+] Export Directory->NumberOfNames: %x\n", ExportDir->NumberOfNames);
    printf("[+] Export Directory->AddressOfFunctions: %x\n", ExportDir->AddressOfFunctions);
    printf("[+] Export Directory->AddressOfNames: %x\n", ExportDir->AddressOfNames);
    printf("[+] Export Directory->AddressOfNameOrdinals: %x\n", ExportDir->AddressOfNameOrdinals);
    for (size_t i = 0; i < ExportDir->NumberOfFunctions; i++)
    {
		printf("\t#%.2x - %s\n", i, rawData + RvaToOffset(rawData, ((DWORD*)(rawData + RvaToOffset(rawData, ExportDir->AddressOfNames)))[i]));
	}   
}
