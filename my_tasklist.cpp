// my_tasklist.cpp
// Supports:
//   my_tasklist
//   my_tasklist /V
//   my_tasklist /SVC
//
// Build (Developer Command Prompt for VS):
//   cl /EHsc /W4 /DUNICODE /D_UNICODE my_tasklist.cpp /link advapi32.lib wtsapi32.lib psapi.lib

#include <windows.h>
#include <tlhelp32.h>
#include <wtsapi32.h>
#include <psapi.h>
#include <sddl.h>
#include <userenv.h>
#include <iostream>
#include <iomanip>
#include <string>
#include <vector>
#include <unordered_map>
#include <algorithm>

#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "wtsapi32.lib")
#pragma comment(lib, "psapi.lib")

using std::wcout;
using std::wcerr;
using std::wstring;
using std::vector;
using std::unordered_map;

struct ProcInfo
{
    DWORD pid = 0;
    DWORD parentPid = 0;
    DWORD threads = 0;
    DWORD sessionId = 0;
    SIZE_T workingSetKB = 0;
    wstring imageName;
    wstring userName;
    wstring created;
};

static wstring ToLower(const wstring& s)
{
    wstring out = s;
    std::transform(out.begin(), out.end(), out.begin(), towlower);
    return out;
}

static wstring FileTimeToStringLocal(const FILETIME& ft)
{
    FILETIME localFt{};
    SYSTEMTIME st{};
    if (!FileTimeToLocalFileTime(&ft, &localFt))
        return L"N/A";
    if (!FileTimeToSystemTime(&localFt, &st))
        return L"N/A";

    wchar_t buf[64];
    swprintf_s(buf, L"%04d-%02d-%02d %02d:%02d:%02d",
        st.wYear, st.wMonth, st.wDay,
        st.wHour, st.wMinute, st.wSecond);
    return buf;
}

static wstring GetProcessUserName(DWORD pid)
{
    HANDLE hProc = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (!hProc)
        return L"N/A";

    HANDLE hToken = nullptr;
    if (!OpenProcessToken(hProc, TOKEN_QUERY, &hToken))
    {
        CloseHandle(hProc);
        return L"N/A";
    }

    DWORD needed = 0;
    GetTokenInformation(hToken, TokenUser, nullptr, 0, &needed);
    if (needed == 0)
    {
        CloseHandle(hToken);
        CloseHandle(hProc);
        return L"N/A";
    }

    vector<BYTE> buffer(needed);
    if (!GetTokenInformation(hToken, TokenUser, buffer.data(), needed, &needed))
    {
        CloseHandle(hToken);
        CloseHandle(hProc);
        return L"N/A";
    }

    TOKEN_USER* tu = reinterpret_cast<TOKEN_USER*>(buffer.data());

    wchar_t name[256];
    wchar_t domain[256];
    DWORD cchName = 256;
    DWORD cchDomain = 256;
    SID_NAME_USE use;

    if (!LookupAccountSidW(nullptr, tu->User.Sid, name, &cchName, domain, &cchDomain, &use))
    {
        CloseHandle(hToken);
        CloseHandle(hProc);
        return L"N/A";
    }

    CloseHandle(hToken);
    CloseHandle(hProc);

    wstring result = domain;
    result += L"\\";
    result += name;
    return result;
}

static SIZE_T GetWorkingSetKB(DWORD pid)
{
    HANDLE hProc = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_VM_READ, FALSE, pid);
    if (!hProc)
        return 0;

    PROCESS_MEMORY_COUNTERS pmc{};
    if (!GetProcessMemoryInfo(hProc, &pmc, sizeof(pmc)))
    {
        CloseHandle(hProc);
        return 0;
    }

    CloseHandle(hProc);
    return pmc.WorkingSetSize / 1024;
}

static wstring GetProcessCreationTime(DWORD pid)
{
    HANDLE hProc = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (!hProc)
        return L"N/A";

    FILETIME createFt{}, exitFt{}, kernelFt{}, userFt{};
    if (!GetProcessTimes(hProc, &createFt, &exitFt, &kernelFt, &userFt))
    {
        CloseHandle(hProc);
        return L"N/A";
    }

    CloseHandle(hProc);
    return FileTimeToStringLocal(createFt);
}

static DWORD GetSessionIdFromPid(DWORD pid)
{
    DWORD sessionId = 0xFFFFFFFF;
    if (!ProcessIdToSessionId(pid, &sessionId))
        return 0xFFFFFFFF;
    return sessionId;
}

static unordered_map<DWORD, vector<wstring>> BuildPidToServicesMap()
{
    unordered_map<DWORD, vector<wstring>> pidServices;

    SC_HANDLE scm = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_ENUMERATE_SERVICE);
    if (!scm)
        return pidServices;

    DWORD bytesNeeded = 0;
    DWORD servicesReturned = 0;
    DWORD resumeHandle = 0;

    EnumServicesStatusExW(
        scm,
        SC_ENUM_PROCESS_INFO,
        SERVICE_WIN32,
        SERVICE_STATE_ALL,
        nullptr,
        0,
        &bytesNeeded,
        &servicesReturned,
        &resumeHandle,
        nullptr
    );

    if (GetLastError() != ERROR_MORE_DATA || bytesNeeded == 0)
    {
        CloseServiceHandle(scm);
        return pidServices;
    }

    vector<BYTE> buffer(bytesNeeded);
    if (!EnumServicesStatusExW(
        scm,
        SC_ENUM_PROCESS_INFO,
        SERVICE_WIN32,
        SERVICE_STATE_ALL,
        buffer.data(),
        static_cast<DWORD>(buffer.size()),
        &bytesNeeded,
        &servicesReturned,
        &resumeHandle,
        nullptr))
    {
        CloseServiceHandle(scm);
        return pidServices;
    }

    ENUM_SERVICE_STATUS_PROCESSW* services =
        reinterpret_cast<ENUM_SERVICE_STATUS_PROCESSW*>(buffer.data());

    for (DWORD i = 0; i < servicesReturned; ++i)
    {
        DWORD pid = services[i].ServiceStatusProcess.dwProcessId;
        if (pid != 0)
        {
            pidServices[pid].push_back(services[i].lpServiceName);
        }
    }

    CloseServiceHandle(scm);
    return pidServices;
}

static vector<ProcInfo> EnumerateProcesses()
{
    vector<ProcInfo> procs;

    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE)
        return procs;

    PROCESSENTRY32W pe{};
    pe.dwSize = sizeof(pe);

    if (!Process32FirstW(snap, &pe))
    {
        CloseHandle(snap);
        return procs;
    }

    do
    {
        ProcInfo p;
        p.pid = pe.th32ProcessID;
        p.parentPid = pe.th32ParentProcessID;
        p.threads = pe.cntThreads;
        p.imageName = pe.szExeFile;
        p.sessionId = GetSessionIdFromPid(p.pid);
        p.userName = GetProcessUserName(p.pid);
        p.workingSetKB = GetWorkingSetKB(p.pid);
        p.created = GetProcessCreationTime(p.pid);

        procs.push_back(p);

    } while (Process32NextW(snap, &pe));

    CloseHandle(snap);
    return procs;
}

static bool HasArg(int argc, wchar_t* argv[], const wchar_t* target)
{
    for (int i = 1; i < argc; ++i)
    {
        if (_wcsicmp(argv[i], target) == 0)
            return true;
    }
    return false;
}

int wmain(int argc, wchar_t* argv[])
{
    bool verbose = HasArg(argc, argv, L"/V");
    bool showSvc = HasArg(argc, argv, L"/SVC");

    auto procs = EnumerateProcesses();
    auto pidToServices = BuildPidToServicesMap();

    if (showSvc)
    {
        wcout << L"Image Name                     PID     Services\n";
        wcout << L"---------------------------------------------------------------\n";

        for (const auto& p : procs)
        {
            wcout << std::left << std::setw(30) << p.imageName
                << std::right << std::setw(8) << p.pid << L"     ";

            auto it = pidToServices.find(p.pid);
            if (it == pidToServices.end())
            {
                wcout << L"N/A";
            }
            else
            {
                for (size_t i = 0; i < it->second.size(); ++i)
                {
                    if (i > 0) wcout << L", ";
                    wcout << it->second[i];
                }
            }
            wcout << L"\n";
        }
        return 0;
    }

    if (verbose)
    {
        wcout << L"Image Name                     PID   SessID Threads    WS(KB)  User                     Created\n";
        wcout << L"---------------------------------------------------------------------------------------------------------------\n";

        for (const auto& p : procs)
        {
            wcout << std::left << std::setw(30) << p.imageName
                << std::right << std::setw(8) << p.pid
                << std::setw(8) << (p.sessionId == 0xFFFFFFFF ? 0 : p.sessionId)
                << std::setw(8) << p.threads
                << std::setw(10) << p.workingSetKB << L"  "
                << std::left << std::setw(25) << p.userName
                << p.created
                << L"\n";
        }
        return 0;
    }

    wcout << L"Image Name                     PID   SessID Threads    WS(KB)\n";
    wcout << L"-----------------------------------------------------------------\n";

    for (const auto& p : procs)
    {
        wcout << std::left << std::setw(30) << p.imageName
            << std::right << std::setw(8) << p.pid
            << std::setw(8) << (p.sessionId == 0xFFFFFFFF ? 0 : p.sessionId)
            << std::setw(8) << p.threads
            << std::setw(10) << p.workingSetKB
            << L"\n";
    }

    return 0;
}