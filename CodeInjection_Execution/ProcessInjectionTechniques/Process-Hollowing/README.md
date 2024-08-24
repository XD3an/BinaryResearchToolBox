# Process Hollowing

- Environment: WIN64, WIN32

## Usage

- Change the PATH of target PE file
    ```cpp
    char *local_PATH = "path\\to\\local_pe";    // temp: :C:\\Windows\\System32\\cmd.exe
    char *remote_PATH = "path\\to\\remote_pe";
    ```
    
- Compile
    ```
    .\setup.bat
    ```
