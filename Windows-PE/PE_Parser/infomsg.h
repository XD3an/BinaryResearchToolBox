#pragma once

#include <windows.h>
#include <winternl.h>
#include <stdio.h>
#include <iostream>

#define info(msg, ...) printf("[*] " msg "\n", ##__VA_ARGS__)
#define okay(msg, ...) printf("[+] " msg "\n", ##__VA_ARGS__)
#define fail(msg, ...) printf("[-] " msg "\n", ##__VA_ARGS__)
#define warn(msg, ...) printf("[!] " msg "\n", ##__VA_ARGS__)