#pragma once

#include <iostream>
#include <windows.h>

typedef struct _MAP_FILE_STRUCT
{
	char* rawData;
	DWORD dRawDataSize;
} MAP_FILE_STRUCT;

BOOL ReadPEFile(const char *filename, MAP_FILE_STRUCT *&mapFile);
BOOL IsPEFile(char*& rawData);
IMAGE_DOS_HEADER* GetDosHeader(char*& rawData);
IMAGE_NT_HEADERS* GetNtHeaders(char*& rawData);
IMAGE_SECTION_HEADER* GetSectionHeader(char*& rawData);
size_t RvaToOffset(char* ExeData, size_t RVA);
void IATParser(char* rawData, DWORD Size);

void PEHdrParser(char* rawData);

