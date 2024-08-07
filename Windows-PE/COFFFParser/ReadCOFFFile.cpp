#include <stdio.h>
#include <Windows.h>

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

int main(int argc, char** argv)
{
    if (argc < 2)
    {
        puts("[!] Usage: .\\ReadCOFFFile.exe [\\path\\to\\coff]");
        return 1;
    }

    char* buf;
    DWORD size;

    // Read the PE file to buf
    if (!ReadBinFile(argv[1], buf, size))
    {
        puts("[!] Read Binary File failed");
        return 1;
    }
    else
    {
        // Print PointerToRawData of each section
        printf("[+] List of PointerToRawData of each section:\n");
        IMAGE_FILE_HEADER* fileHeader = (IMAGE_FILE_HEADER*)buf;
        IMAGE_SECTION_HEADER* secHeader = (IMAGE_SECTION_HEADER*)(buf + sizeof(IMAGE_FILE_HEADER));
        for (int i = 0; i < (fileHeader->NumberOfSections); i++)
        {
            printf("    %s: %p\n", secHeader[i].Name, secHeader[i].PointerToRawData);
        }
    }
    

    return 0;
}