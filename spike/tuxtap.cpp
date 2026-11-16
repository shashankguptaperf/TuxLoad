// tuxtap.cpp
// Phase-0 spike for TuxLoad. Loaded into a 64-bit Tuxedo client by tuxtap-launch.exe.
//
// It patches the import table of every loaded module that imports tpcall, so each call is
// logged (service name, buffer type, sizes, return code, elapsed time) and then forwarded to
// the real tpcall. Nothing on disk is changed.
//
// NOT TESTED. Build with build.bat from an x64 Native Tools prompt.
//
// Limits of this spike:
//   - tpcall only. tpacall, tpgetrply, tpconnect/tpsend/tprecv are not logged yet.
//   - Calls made through GetProcAddress or delay-loaded imports are not seen.
//   - The tpcall prototype is declared here, not read from atmi.h. Check it against
//     the include folder on the server before relying on the output.

#define _CRT_SECURE_NO_WARNINGS
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <psapi.h>
#include <stdio.h>
#include <string.h>

#pragma comment(lib, "psapi.lib")

typedef int  (__cdecl *tpcall_fn)(char *svc, char *idata, long ilen, char **odata, long *olen, long flags);
typedef long (__cdecl *tptypes_fn)(char *ptr, char *type, char *subtype);

static tpcall_fn        g_realTpcall = NULL;
static tptypes_fn       g_tptypes = NULL;
static CRITICAL_SECTION g_lock;
static FILE            *g_log = NULL;
static LARGE_INTEGER    g_freq;
// TUXTAP_DUMP=1 writes the first 64 bytes of each request as hex.
// Request buffers can contain customer data, so this is off by default.
static BOOL             g_dump = FALSE;

static void log_text(const char *text)
{
    EnterCriticalSection(&g_lock);
    if (g_log) {
        fputs(text, g_log);
        fflush(g_log);
    }
    LeaveCriticalSection(&g_lock);
}

static void log_call(const char *svc, const char *type, const char *subtype,
                     long ilen, long olen_after, long flags, int rc, double us, const char *dump)
{
    SYSTEMTIME st;
    char line[1024];

    GetLocalTime(&st);
    snprintf(line, sizeof(line),
             "%04d-%02d-%02d %02d:%02d:%02d.%03d\t%lu\t%s\t%s\t%s\t%ld\t%ld\t%ld\t%d\t%.1f%s\n",
             st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond, st.wMilliseconds,
             GetCurrentThreadId(), svc, type, subtype, ilen, olen_after, flags, rc, us, dump);
    log_text(line);
}

static int __cdecl hooked_tpcall(char *svc, char *idata, long ilen, char **odata, long *olen, long flags)
{
    char type[16] = "-";
    char subtype[32] = "-";
    char dump[200] = "";
    LARGE_INTEGER t0, t1;
    double us;
    int rc;
    long olen_after = -1;

    if (g_tptypes && idata) {
        __try {
            if (g_tptypes(idata, type, subtype) < 0) {
                strcpy(type, "untyped");
                strcpy(subtype, "-");
            }
        } __except (EXCEPTION_EXECUTE_HANDLER) {
            strcpy(type, "unknown");
            strcpy(subtype, "-");
        }
    }

    if (g_dump && idata && ilen > 0) {
        long n = ilen < 64 ? ilen : 64;
        int off = snprintf(dump, sizeof(dump), "\tHEX:");
        long i;
        for (i = 0; i < n && off < (int)sizeof(dump) - 3; ++i) {
            off += snprintf(dump + off, sizeof(dump) - off, "%02x", (unsigned char)idata[i]);
        }
    }

    QueryPerformanceCounter(&t0);
    rc = g_realTpcall(svc, idata, ilen, odata, olen, flags);
    QueryPerformanceCounter(&t1);

    us = (double)(t1.QuadPart - t0.QuadPart) * 1000000.0 / (double)g_freq.QuadPart;
    if (olen) olen_after = *olen;
    log_call(svc ? svc : "(null)", type, subtype, ilen, olen_after, flags, rc, us, dump);
    return rc;
}

static void patch_module(HMODULE mod)
{
    BYTE *base = (BYTE *)mod;
    IMAGE_DOS_HEADER *dos = (IMAGE_DOS_HEADER *)base;
    IMAGE_NT_HEADERS *nt;
    IMAGE_DATA_DIRECTORY dir;
    IMAGE_IMPORT_DESCRIPTOR *imp;
    char modName[MAX_PATH] = "";

    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return;
    nt = (IMAGE_NT_HEADERS *)(base + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) return;
    dir = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    if (dir.VirtualAddress == 0) return;

    for (imp = (IMAGE_IMPORT_DESCRIPTOR *)(base + dir.VirtualAddress); imp->Name; ++imp) {
        IMAGE_THUNK_DATA *iat = (IMAGE_THUNK_DATA *)(base + imp->FirstThunk);
        IMAGE_THUNK_DATA *ilt = imp->OriginalFirstThunk
            ? (IMAGE_THUNK_DATA *)(base + imp->OriginalFirstThunk)
            : iat;

        for (; ilt->u1.AddressOfData; ++ilt, ++iat) {
            IMAGE_IMPORT_BY_NAME *byName;
            DWORD oldProtect = 0;

            if (ilt->u1.Ordinal & IMAGE_ORDINAL_FLAG) continue;
            byName = (IMAGE_IMPORT_BY_NAME *)(base + ilt->u1.AddressOfData);
            if (strcmp((const char *)byName->Name, "tpcall") != 0) continue;
            if ((void *)iat->u1.Function == (void *)hooked_tpcall) continue;

            if (!g_realTpcall) g_realTpcall = (tpcall_fn)iat->u1.Function;
            if (!VirtualProtect(&iat->u1.Function, sizeof(iat->u1.Function), PAGE_READWRITE, &oldProtect)) continue;
            iat->u1.Function = (ULONGLONG)(ULONG_PTR)hooked_tpcall;
            VirtualProtect(&iat->u1.Function, sizeof(iat->u1.Function), oldProtect, &oldProtect);

            if (modName[0] == '\0') GetModuleFileNameA(mod, modName, sizeof(modName));
            {
                char line[MAX_PATH + 128];
                snprintf(line, sizeof(line), "# patched tpcall import in %s\n", modName);
                log_text(line);
            }
        }
    }
}

static void scan_modules(void)
{
    HMODULE mods[1024];
    DWORD needed = 0;
    DWORD count, i;

    if (!EnumProcessModules(GetCurrentProcess(), mods, sizeof(mods), &needed)) return;
    count = needed / sizeof(HMODULE);
    if (count > 1024) count = 1024;

    for (i = 0; i < count; ++i) {
        if (!g_tptypes) {
            FARPROC p = GetProcAddress(mods[i], "tptypes");
            if (p) g_tptypes = (tptypes_fn)p;
        }
        patch_module(mods[i]);
    }
}

// Runs every 250 ms so modules loaded after startup (for example pbtux64.dll) are also patched.
static DWORD WINAPI scan_thread(LPVOID unused)
{
    (void)unused;
    for (;;) {
        scan_modules();
        Sleep(250);
    }
    return 0;
}

BOOL APIENTRY DllMain(HMODULE module, DWORD reason, LPVOID reserved)
{
    (void)reserved;
    if (reason == DLL_PROCESS_ATTACH) {
        char path[MAX_PATH];
        char tmp[MAX_PATH];
        DWORD n;

        DisableThreadLibraryCalls(module);
        InitializeCriticalSection(&g_lock);
        QueryPerformanceFrequency(&g_freq);
        g_dump = GetEnvironmentVariableA("TUXTAP_DUMP", NULL, 0) > 0;

        n = GetEnvironmentVariableA("TUXTAP_LOG", path, sizeof(path));
        if (n == 0 || n >= sizeof(path)) {
            GetTempPathA(sizeof(tmp), tmp);
            snprintf(path, sizeof(path), "%stuxtap-%lu.log", tmp, GetCurrentProcessId());
        }
        g_log = fopen(path, "a");
        if (g_log) fprintf(g_log, "# tuxtap attached pid=%lu\n", GetCurrentProcessId());

        CreateThread(NULL, 0, scan_thread, NULL, 0, NULL);
    }
    return TRUE;
}
