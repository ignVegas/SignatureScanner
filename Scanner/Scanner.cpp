#include "Scanner.h"

std::vector<std::string> unsignedExecutables;

std::string WStringToString(const std::wstring& wstr)
{
    int sizeNeeded = WideCharToMultiByte(CP_UTF8, 0, wstr.c_str(), -1, NULL, 0, NULL, NULL);
    std::string str(sizeNeeded, 0);
    WideCharToMultiByte(CP_UTF8, 0, wstr.c_str(), -1, &str[0], sizeNeeded, NULL, NULL);
    return str;
}

bool VerifySignature(const std::wstring& filePath)
{
    WINTRUST_FILE_INFO fileInfo = { 0 };
    fileInfo.cbStruct = sizeof(WINTRUST_FILE_INFO);
    fileInfo.pcwszFilePath = filePath.c_str();

    WINTRUST_DATA trustData = { 0 };
    trustData.cbStruct = sizeof(WINTRUST_DATA);
    trustData.dwUIChoice = WTD_UI_NONE;
    trustData.fdwRevocationChecks = WTD_REVOKE_NONE;
    trustData.dwUnionChoice = WTD_CHOICE_FILE;
    trustData.pFile = &fileInfo;
    trustData.dwStateAction = WTD_STATEACTION_VERIFY;

    GUID policyGUID = WINTRUST_ACTION_GENERIC_VERIFY_V2;
    LONG status = WinVerifyTrust(NULL, &policyGUID, &trustData);

    trustData.dwStateAction = WTD_STATEACTION_CLOSE;
    WinVerifyTrust(NULL, &policyGUID, &trustData);

    if (status == TRUST_E_NOSIGNATURE)
    {
        // The file has no signature
        std::cout << "No signature found for: " << WStringToString(filePath) << std::endl;
        return true; // Treat as signed (or modify this based on your requirements)
    }
    else if (status == CERT_E_UNTRUSTEDROOT)
    {
        // The certificate chain is not trusted
        std::cout << "Untrusted root certificate for: " << WStringToString(filePath) << std::endl;
        return false;
    }
    else if (status == CERT_E_REVOKED)
    {
        // The certificate has been revoked
        std::cout << "Revoked certificate for: " << WStringToString(filePath) << std::endl;
        return false;
    }
    else if (status != ERROR_SUCCESS)
    {
        // Signature verification failed
        std::cout << "Signature verification failed for: " << WStringToString(filePath) << " (error: " << std::hex << status << ")" << std::endl;
        return false;
    }

    // Signature is valid
    std::cout << "Signature verified for: " << WStringToString(filePath) << std::endl;
    return true;
}



std::unordered_set<std::string> legitimateProcesses = {
    "explorer.exe",
    "svchost.exe",
    "csrss.exe",
    "wininit.exe",
    "lsass.exe",
    "services.exe",
    "smss.exe",
    "taskhostw.exe",
    "sihost.exe",
    "runtimebroker.exe",
    "ctfmon.exe",
    "dllhost.exe",
    "audiodg.exe",
    "conhost.exe",
    "cl.exe",
    "msbuild.exe",
    "vshost.exe",
    "vcpkgsrv.exe",
    "taskmgr.exe",
    "winrar.exe",
    "discord.exe",
    "steam.exe",
    "steamwebhelper.exe",
    "wallpaper32.exe",
    "msiafterburner.exe",
    "velocityx.exe",
    "searchhost.exe",
    "startmenuexperiencehost.exe",
    "shellexperiencehost.exe",
    "systemsettingsbroker.exe",
    "vgtray.exe",
    "riotclientservices.exe",
    "riotclientcrashhandler.exe",
    "ccleaner64.exe",
    "x3.exe",
    "opera_crashreporter.exe",
    "vctip.exe",
    "devenv.exe",
    "perfwatson2.exe",
    "microsoft.servicehub.controller.exe",
    "servicehub.vsdetouredhost.exe",
    "servicehub.threadedwaitdialog.exe",
    "servicehub.identityhost.exe",
    "servicehub.indexingservice.exe",
    "servicehub.intellicodemodelservice.exe",
    "servicehub.host.dotnet.x64.exe",
    "servicehub.roslyncodeanalysisservice.exe",
    "copilot-agent-win.exe",
    "servicehub.host.anycpu.exe",
    "servicehub.testwindowstorehost.exe",
    "signaturescanner.exe",
    "opera.exe"
};


std::string ToLower(const std::string& str)
{
    std::string lowerStr = str;
    std::transform(lowerStr.begin(), lowerStr.end(), lowerStr.begin(), ::tolower);
    return lowerStr;
}

void ScanProcesses()
{
    unsignedExecutables.clear();
    std::unordered_set<std::string> scannedExes;  // To track already scanned executables

    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot == INVALID_HANDLE_VALUE)
    {
        std::cout << "Failed to create process snapshot." << std::endl;
        return;
    }

    PROCESSENTRY32 pe32;
    pe32.dwSize = sizeof(PROCESSENTRY32);

    bool accessDeniedLogged = false;  // To log access denied errors only once

    if (Process32First(snapshot, &pe32))
    {
        do
        {
            // Open the process
            HANDLE hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pe32.th32ProcessID);
            if (hProcess)
            {
                WCHAR filePath[MAX_PATH];
                DWORD size = MAX_PATH;

                if (QueryFullProcessImageName(hProcess, 0, filePath, &size))
                {
                    std::wstring wFilePath(filePath);

                    // Convert the wide string to a standard string
                    std::string processPath = WStringToString(wFilePath);

                    // Extract the executable name using std::filesystem
                    std::filesystem::path pathObj(processPath);
                    std::string exeName = pathObj.filename().string(); // Extract "opera.exe"

                    // Trim leading/trailing whitespace
                    exeName.erase(0, exeName.find_first_not_of(" \t\n\r\f\v"));
                    exeName.erase(exeName.find_last_not_of(" \t\n\r\f\v") + 1);

                    // Convert the executable name to lowercase
                    std::string lowerExeName = ToLower(exeName);

                    // Skip already scanned executables
                    if (scannedExes.find(lowerExeName) != scannedExes.end())
                    {
                        std::cout << "Skipping already scanned executable: " << exeName << std::endl;
                        CloseHandle(hProcess);
                        continue;
                    }

                    // Add the exe to scanned list
                    scannedExes.insert(lowerExeName);

                    // **Critical Fix**: Skip legitimate processes **before** signature check
                    if (legitimateProcesses.find(lowerExeName) != legitimateProcesses.end())
                    {
                        std::cout << "Skipping legitimate process: " << exeName << std::endl;
                        CloseHandle(hProcess); // Close the handle before continuing
                        continue;
                    }

                    // Check if the executable has a valid signature if it's not legitimate
                    if (!VerifySignature(wFilePath))
                    {
                        unsignedExecutables.push_back(exeName);
                        std::cout << "Unsigned executable found: " << exeName << std::endl;
                    }
                    else
                    {
                        std::cout << "Signed executable found: " << exeName << std::endl;
                    }
                }
                else
                {
                    std::cout << "Failed to query full process name for PID: " << pe32.th32ProcessID << std::endl;
                }

                CloseHandle(hProcess);
            }
            else
            {
                DWORD error = GetLastError();
                if (error == ERROR_ACCESS_DENIED)
                {
                    // Print once for access denied errors
                    if (!accessDeniedLogged)
                    {
                        std::cout << "Access denied for system process (likely): " << pe32.th32ProcessID << std::endl;
                        accessDeniedLogged = true;
                    }
                }
                else
                {
                    std::cout << "Failed to open process with PID: " << pe32.th32ProcessID << " (error: " << error << ")" << std::endl;
                }
            }
        } while (Process32Next(snapshot, &pe32));
    }
    else
    {
        std::cout << "Failed to retrieve process information." << std::endl;
    }

    CloseHandle(snapshot);
}