// tuxtap-launch.cpp
// Starts a 64-bit client suspended, loads tuxtap.dll into it, then resumes it.
// Build as a 64-bit program, the same bitness as the client it starts.
//
// Usage (run from a cmd window that has the client's environment set):
//   tuxtap-launch.exe "D:\apps\V21\st_b\Bin32\a_tlg32.exe"
//
// NOT TESTED.

#define _CRT_SECURE_NO_WARNINGS
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdio.h>
#include <string.h>

int main(int argc, char **argv)
{
    char dllPath[MAX_PATH];
    char exeDir[MAX_PATH];
    char cmd[4096];
    STARTUPINFOA si;
    PROCESS_INFORMATION pi;
    LPVOID remote;
    SIZE_T len;
    HANDLE th;
    DWORD exitCode = 0;
    FARPROC loadLib;
    int i;

    if (argc < 2) {
        fprintf(stderr, "usage: tuxtap-launch.exe <client.exe> [args]\n");
        return 2;
    }

    GetModuleFileNameA(NULL, exeDir, sizeof(exeDir));
    {
        char *slash = strrchr(exeDir, '\\');
        if (slash) *(slash + 1) = '\0';
    }
    snprintf(dllPath, sizeof(dllPath), "%stuxtap.dll", exeDir);
    if (GetFileAttributesA(dllPath) == INVALID_FILE_ATTRIBUTES) {
        fprintf(stderr, "tuxtap.dll not found next to the launcher: %s\n", dllPath);
        return 1;
    }

    snprintf(cmd, sizeof(cmd), "\"%s\"", argv[1]);
    for (i = 2; i < argc; ++i) {
        strncat(cmd, " ", sizeof(cmd) - strlen(cmd) - 1);
        strncat(cmd, argv[i], sizeof(cmd) - strlen(cmd) - 1);
    }

    memset(&si, 0, sizeof(si));
    si.cb = sizeof(si);
    memset(&pi, 0, sizeof(pi));
    if (!CreateProcessA(NULL, cmd, NULL, NULL, FALSE, CREATE_SUSPENDED, NULL, NULL, &si, &pi)) {
        fprintf(stderr, "CreateProcess failed (%lu)\n", GetLastError());
        return 1;
    }

    len = strlen(dllPath) + 1;
    remote = VirtualAllocEx(pi.hProcess, NULL, len, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!remote || !WriteProcessMemory(pi.hProcess, remote, dllPath, len, NULL)) {
        fprintf(stderr, "could not write the DLL path into the client (%lu)\n", GetLastError());
        TerminateProcess(pi.hProcess, 1);
        return 1;
    }

    loadLib = GetProcAddress(GetModuleHandleA("kernel32.dll"), "LoadLibraryA");
    th = CreateRemoteThread(pi.hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)loadLib, remote, 0, NULL);
    if (!th) {
        fprintf(stderr, "CreateRemoteThread failed (%lu)\n", GetLastError());
        TerminateProcess(pi.hProcess, 1);
        return 1;
    }
    WaitForSingleObject(th, 10000);
    GetExitCodeThread(th, &exitCode);
    CloseHandle(th);
    VirtualFreeEx(pi.hProcess, remote, 0, MEM_RELEASE);

    if (exitCode == 0) {
        fprintf(stderr, "tuxtap.dll did not load into the client\n");
        TerminateProcess(pi.hProcess, 1);
        return 1;
    }

    ResumeThread(pi.hThread);
    printf("started pid %lu with tuxtap.dll loaded\n", pi.dwProcessId);
    printf("log: %%TUXTAP_LOG%% or %%TEMP%%\\tuxtap-%lu.log\n", pi.dwProcessId);
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
    return 0;
}
