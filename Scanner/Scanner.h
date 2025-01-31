
#include <windows.h>
#include <tlhelp32.h>
#include <wincrypt.h>
#include <wintrust.h>
#include <vector>
#include <string>
#include <psapi.h>
#include <iostream>
#include <unordered_set>
#include <filesystem>
#include <algorithm>

const GUID WINTRUST_ACTION_GENERIC_VERIFY_V2 =
{ 0xaac56b, 0xcd44, 0x11d0, { 0x8c, 0xc2, 0xc0, 0x4f, 0xc2, 0x94, 0x66 } };


// Link necessary libraries
#pragma comment(lib, "wintrust.lib")

extern std::vector<std::string> unsignedExecutables;

void ScanProcesses();
bool VerifySignature(const std::wstring& filePath);
