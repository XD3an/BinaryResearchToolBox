#include <stdio.h>
#include <windows.h>
#pragma warning(disable : 4996)
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


void FixIAT(char* peImage)
{
	auto IATDir = getNtHdr(peImage)->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
	auto impModuleList = (IMAGE_IMPORT_DESCRIPTOR*)&peImage[IATDir.VirtualAddress];
	for (HMODULE currMod; impModuleList->Name; impModuleList++)
	{
		printf("\timport module : %s\n", &peImage[impModuleList->Name]);
		currMod = LoadLibraryA(&peImage[impModuleList->Name]);

		auto arr_callVia = (IMAGE_THUNK_DATA*)&peImage[impModuleList->FirstThunk];
		for (int count = 0; arr_callVia->u1.Function; count++, arr_callVia++)
		{
			auto curr_impApi = (PIMAGE_IMPORT_BY_NAME)&peImage[arr_callVia->u1.Function];
			arr_callVia->u1.Function = (size_t)GetProcAddress(currMod, (char*)curr_impApi->Name);
			printf("\t\t- fix import function: %s\n", curr_impApi->Name);
		}
	}
}
void invoke_memExe(char* exeData)
{
	auto imgBaseAt = (void*)getNtHdr(exeData)->OptionalHeader.ImageBase;
	auto imgSize = getNtHdr(exeData)->OptionalHeader.SizeOfImage;
	if (char* peImage = (char*)VirtualAlloc(imgBaseAt, imgSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE))
	{
		printf("[+] exe file mapped @ %p\n", peImage);
		memcpy(peImage, exeData, getNtHdr(exeData)->OptionalHeader.SizeOfHeaders);
		for (int i = 0; i < getNtHdr(exeData)->FileHeader.NumberOfSections; i++)
		{
			auto curr_section = getSectionArr(exeData)[i];
			memcpy(
				&peImage[curr_section.VirtualAddress],
				&exeData[curr_section.PointerToRawData],
				curr_section.SizeOfRawData);
		}
		printf("[+] file mapping ok\n");

		FixIAT(peImage);
		printf("[+] fix iat.\n");

		auto addrOfEntry = getNtHdr(exeData)->OptionalHeader.AddressOfEntryPoint;
		printf("[+] invoke entry @ %p ...\n", &peImage[addrOfEntry]);
		((void (*)()) & peImage[addrOfEntry])();
	}
	else
		printf("[-] alloc memory for exe @ %p failure.\n", imgBaseAt);
}

int main(int argc, char** argv)
{
	char* exeBuf;
	DWORD exeSize;

	if (argc != 2)
		puts("[!] Usage: .\\invoke_Exe_in_memory.exe [path\\to\\exe]");
	else if (ReadBinFile(argv[1], exeBuf, exeSize))
		invoke_memExe(exeBuf);
	else
		puts("[!] exe file not found.");
	return 0;
}