// my_taskkill.cpp
// Supports:
//   my_taskkill /PID <pid> [/F] [/T]
//   my_taskkill /IM <image.exe> [/F] [/T]
//   my_taskkill /S <system> /U <domain\user> [/P <password>] /PID <pid> [/F] [/T]
//   my_taskkill /S <system> /U <domain\user> [/P <password>] /IM <image.exe> [/F] [/T]
//
// Notes:
// - /F is accepted for compatibility; TerminateProcess/WMI Terminate are already forceful.
// - /S and /U are implemented using WMI.
// - /P is optional but strongly recommended for remote authentication.
//
// Build:
// cl /EHsc /W4 /DUNICODE /D_UNICODE my_taskkill.cpp /link advapi32.lib wbemuuid.lib ole32.lib oleaut32.lib

#include <windows.h>
#include <tlhelp32.h>
#include <wbemidl.h>
#include <comdef.h>
#include <iostream>
#include <string>
#include <vector>
#include <set>
#include <map>
#include <algorithm>

#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "wbemuuid.lib")
#pragma comment(lib, "ole32.lib")
#pragma comment(lib, "oleaut32.lib")

using std::wcout;
using std::wcerr;
using std::wstring;
using std::vector;
using std::set;
using std::map;

struct ProcessNode
{
    DWORD pid = 0;
    DWORD parentPid = 0;
    wstring imageName;
};

static wstring ToLower(const wstring& s)
{
    wstring out = s;
    std::transform(out.begin(), out.end(), out.begin(), towlower);
    return out;
}

static bool StartsWithSlash(const wchar_t* s)
{
    return s && (s[0] == L'/' || s[0] == L'-');
}

static bool ParsePidArg(const wstring& s, DWORD& pidOut)
{
    try
    {
        unsigned long value = std::stoul(s);
        pidOut = static_cast<DWORD>(value);
        return true;
    }
    catch (...)
    {
        return false;
    }
}

static vector<ProcessNode> SnapshotProcessesLocal()
{
    vector<ProcessNode> list;

    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE)
        return list;

    PROCESSENTRY32W pe{};
    pe.dwSize = sizeof(pe);

    if (!Process32FirstW(snap, &pe))
    {
        CloseHandle(snap);
        return list;
    }

    do
    {
        ProcessNode p;
        p.pid = pe.th32ProcessID;
        p.parentPid = pe.th32ParentProcessID;
        p.imageName = pe.szExeFile;
        list.push_back(p);
    } while (Process32NextW(snap, &pe));

    CloseHandle(snap);
    return list;
}

static void CollectChildrenRecursiveLocal(DWORD parent, const vector<ProcessNode>& all, set<DWORD>& out)
{
    for (const auto& p : all)
    {
        if (p.parentPid == parent && out.find(p.pid) == out.end())
        {
            out.insert(p.pid);
            CollectChildrenRecursiveLocal(p.pid, all, out);
        }
    }
}

static vector<DWORD> FindPidsByImageLocal(const wstring& image)
{
    vector<DWORD> pids;
    auto all = SnapshotProcessesLocal();
    wstring target = ToLower(image);

    for (const auto& p : all)
    {
        if (ToLower(p.imageName) == target)
            pids.push_back(p.pid);
    }

    return pids;
}

static bool KillOneProcessLocal(DWORD pid)
{
    HANDLE hProc = OpenProcess(PROCESS_TERMINATE | PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (!hProc)
        return false;

    BOOL ok = TerminateProcess(hProc, 1);
    CloseHandle(hProc);
    return ok == TRUE;
}

static wstring EscapeWqlString(const wstring& s)
{
    wstring out;
    for (wchar_t c : s)
    {
        if (c == L'\'')
            out += L"''";
        else
            out += c;
    }
    return out;
}

class ComInit
{
public:
    ComInit() : initialized(false), securityInitialized(false) {}

    HRESULT Init()
    {
        HRESULT hr = CoInitializeEx(nullptr, COINIT_MULTITHREADED);
        if (SUCCEEDED(hr) || hr == RPC_E_CHANGED_MODE)
        {
            initialized = true;
        }
        else
        {
            return hr;
        }

        hr = CoInitializeSecurity(
            nullptr,
            -1,
            nullptr,
            nullptr,
            RPC_C_AUTHN_LEVEL_DEFAULT,
            RPC_C_IMP_LEVEL_IMPERSONATE,
            nullptr,
            EOAC_NONE,
            nullptr);

        if (SUCCEEDED(hr))
        {
            securityInitialized = true;
            return S_OK;
        }

        // If already initialized elsewhere, that's okay.
        if (hr == RPC_E_TOO_LATE)
            return S_OK;

        return hr;
    }

    ~ComInit()
    {
        if (initialized)
            CoUninitialize();
    }

private:
    bool initialized;
    bool securityInitialized;
};

static bool SplitDomainUser(const wstring& full, wstring& domain, wstring& user)
{
    size_t pos = full.find(L'\\');
    if (pos == wstring::npos)
        return false;

    domain = full.substr(0, pos);
    user = full.substr(pos + 1);
    return !domain.empty() && !user.empty();
}

static HRESULT ConnectWmi(
    const wstring& server,
    const wstring& user,
    const wstring& password,
    IWbemServices** servicesOut)
{
    if (!servicesOut)
        return E_POINTER;

    *servicesOut = nullptr;

    IWbemLocator* pLoc = nullptr;
    HRESULT hr = CoCreateInstance(
        CLSID_WbemLocator,
        nullptr,
        CLSCTX_INPROC_SERVER,
        IID_IWbemLocator,
        reinterpret_cast<LPVOID*>(&pLoc));

    if (FAILED(hr))
        return hr;

    wstring path = L"\\\\";
    path += server;
    path += L"\\root\\cimv2";

    BSTR ns = SysAllocString(path.c_str());
    BSTR usr = user.empty() ? nullptr : SysAllocString(user.c_str());
    BSTR pwd = password.empty() ? nullptr : SysAllocString(password.c_str());

    IWbemServices* pSvc = nullptr;
    hr = pLoc->ConnectServer(
        ns,
        usr,
        pwd,
        nullptr,
        0,
        nullptr,
        nullptr,
        &pSvc);

    if (ns) SysFreeString(ns);
    if (usr) SysFreeString(usr);
    if (pwd) SysFreeString(pwd);
    pLoc->Release();

    if (FAILED(hr))
        return hr;

    hr = CoSetProxyBlanket(
        pSvc,
        RPC_C_AUTHN_WINNT,
        RPC_C_AUTHZ_NONE,
        nullptr,
        RPC_C_AUTHN_LEVEL_CALL,
        RPC_C_IMP_LEVEL_IMPERSONATE,
        nullptr,
        EOAC_NONE);

    if (FAILED(hr))
    {
        pSvc->Release();
        return hr;
    }

    *servicesOut = pSvc;
    return S_OK;
}

static vector<ProcessNode> SnapshotProcessesRemote(IWbemServices* pSvc)
{
    vector<ProcessNode> list;
    if (!pSvc)
        return list;

    IEnumWbemClassObject* pEnumerator = nullptr;

    BSTR lang = SysAllocString(L"WQL");
    BSTR query = SysAllocString(L"SELECT Handle, ParentProcessId, Name FROM Win32_Process");

    HRESULT hr = pSvc->ExecQuery(
        lang,
        query,
        WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY,
        nullptr,
        &pEnumerator);

    SysFreeString(lang);
    SysFreeString(query);

    if (FAILED(hr) || !pEnumerator)
        return list;

    while (true)
    {
        IWbemClassObject* pObj = nullptr;
        ULONG returned = 0;

        hr = pEnumerator->Next(WBEM_INFINITE, 1, &pObj, &returned);
        if (FAILED(hr) || returned == 0)
            break;

        VARIANT vtHandle, vtParent, vtName;
        VariantInit(&vtHandle);
        VariantInit(&vtParent);
        VariantInit(&vtName);

        ProcessNode p;

        if (SUCCEEDED(pObj->Get(L"Handle", 0, &vtHandle, nullptr, nullptr)) &&
            vtHandle.vt == VT_BSTR && vtHandle.bstrVal)
        {
            p.pid = static_cast<DWORD>(_wtoi(vtHandle.bstrVal));
        }

        if (SUCCEEDED(pObj->Get(L"ParentProcessId", 0, &vtParent, nullptr, nullptr)))
        {
            if (vtParent.vt == VT_I4 || vtParent.vt == VT_UI4)
                p.parentPid = vtParent.uintVal;
        }

        if (SUCCEEDED(pObj->Get(L"Name", 0, &vtName, nullptr, nullptr)) &&
            vtName.vt == VT_BSTR && vtName.bstrVal)
        {
            p.imageName = vtName.bstrVal;
        }

        if (p.pid != 0)
            list.push_back(p);

        VariantClear(&vtHandle);
        VariantClear(&vtParent);
        VariantClear(&vtName);
        pObj->Release();
    }

    pEnumerator->Release();
    return list;
}

static vector<DWORD> FindPidsByImageRemote(IWbemServices* pSvc, const wstring& image)
{
    vector<DWORD> pids;
    if (!pSvc)
        return pids;

    wstring queryStr = L"SELECT Handle FROM Win32_Process WHERE Name='";
    queryStr += EscapeWqlString(image);
    queryStr += L"'";

    IEnumWbemClassObject* pEnumerator = nullptr;
    BSTR lang = SysAllocString(L"WQL");
    BSTR query = SysAllocString(queryStr.c_str());

    HRESULT hr = pSvc->ExecQuery(
        lang,
        query,
        WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY,
        nullptr,
        &pEnumerator);

    SysFreeString(lang);
    SysFreeString(query);

    if (FAILED(hr) || !pEnumerator)
        return pids;

    while (true)
    {
        IWbemClassObject* pObj = nullptr;
        ULONG returned = 0;

        hr = pEnumerator->Next(WBEM_INFINITE, 1, &pObj, &returned);
        if (FAILED(hr) || returned == 0)
            break;

        VARIANT vtHandle;
        VariantInit(&vtHandle);

        if (SUCCEEDED(pObj->Get(L"Handle", 0, &vtHandle, nullptr, nullptr)) &&
            vtHandle.vt == VT_BSTR && vtHandle.bstrVal)
        {
            pids.push_back(static_cast<DWORD>(_wtoi(vtHandle.bstrVal)));
        }

        VariantClear(&vtHandle);
        pObj->Release();
    }

    pEnumerator->Release();
    return pids;
}

static void CollectChildrenRecursiveRemote(DWORD parent, const vector<ProcessNode>& all, set<DWORD>& out)
{
    for (const auto& p : all)
    {
        if (p.parentPid == parent && out.find(p.pid) == out.end())
        {
            out.insert(p.pid);
            CollectChildrenRecursiveRemote(p.pid, all, out);
        }
    }
}

static bool KillOneProcessRemote(IWbemServices* pSvc, DWORD pid)
{
    if (!pSvc)
        return false;

    IWbemClassObject* pClass = nullptr;
    HRESULT hr = pSvc->GetObject(_bstr_t(L"Win32_Process"), 0, nullptr, &pClass, nullptr);
    if (FAILED(hr) || !pClass)
        return false;

    IWbemClassObject* pInSig = nullptr;
    hr = pClass->GetMethod(L"Terminate", 0, &pInSig, nullptr);
    if (FAILED(hr) || !pInSig)
    {
        pClass->Release();
        return false;
    }

    IWbemClassObject* pInInst = nullptr;
    hr = pInSig->SpawnInstance(0, &pInInst);
    if (FAILED(hr) || !pInInst)
    {
        pInSig->Release();
        pClass->Release();
        return false;
    }

    VARIANT vtReason;
    VariantInit(&vtReason);
    vtReason.vt = VT_I4;
    vtReason.lVal = 1;
    pInInst->Put(L"Reason", 0, &vtReason, 0);
    VariantClear(&vtReason);

    wchar_t objectPath[128];
    swprintf_s(objectPath, L"Win32_Process.Handle=\"%lu\"", pid);

    IWbemClassObject* pOut = nullptr;
    hr = pSvc->ExecMethod(
        _bstr_t(objectPath),
        _bstr_t(L"Terminate"),
        0,
        nullptr,
        pInInst,
        &pOut,
        nullptr);

    pInInst->Release();
    pInSig->Release();
    pClass->Release();

    if (FAILED(hr))
    {
        if (pOut) pOut->Release();
        return false;
    }

    bool success = false;
    if (pOut)
    {
        VARIANT vtRet;
        VariantInit(&vtRet);

        if (SUCCEEDED(pOut->Get(L"ReturnValue", 0, &vtRet, nullptr, 0)))
        {
            if ((vtRet.vt == VT_I4 || vtRet.vt == VT_UI4) && vtRet.uintVal == 0)
                success = true;
        }

        VariantClear(&vtRet);
        pOut->Release();
    }

    return success;
}

int wmain(int argc, wchar_t* argv[])
{
    if (argc < 3)
    {
        wcout << L"Usage:\n"
            << L"  my_taskkill /PID <pid> [/F] [/T]\n"
            << L"  my_taskkill /IM <image.exe> [/F] [/T]\n"
            << L"  my_taskkill /S <system> /U <domain\\user> [/P <password>] /PID <pid> [/F] [/T]\n"
            << L"  my_taskkill /S <system> /U <domain\\user> [/P <password>] /IM <image.exe> [/F] [/T]\n";
        return 1;
    }

    bool forceFlag = false;
    bool treeFlag = false;
    bool byPid = false;
    bool byImage = false;

    wstring systemName;
    wstring userName;
    wstring password;
    DWORD pid = 0;
    wstring imageName;

    for (int i = 1; i < argc; ++i)
    {
        if (_wcsicmp(argv[i], L"/F") == 0)
        {
            forceFlag = true;
        }
        else if (_wcsicmp(argv[i], L"/T") == 0)
        {
            treeFlag = true;
        }
        else if (_wcsicmp(argv[i], L"/S") == 0 && i + 1 < argc)
        {
            systemName = argv[++i];
        }
        else if (_wcsicmp(argv[i], L"/U") == 0 && i + 1 < argc)
        {
            userName = argv[++i];
        }
        else if (_wcsicmp(argv[i], L"/P") == 0 && i + 1 < argc)
        {
            password = argv[++i];
        }
        else if (_wcsicmp(argv[i], L"/PID") == 0 && i + 1 < argc)
        {
            if (!ParsePidArg(argv[++i], pid))
            {
                wcerr << L"Invalid PID.\n";
                return 1;
            }
            byPid = true;
        }
        else if (_wcsicmp(argv[i], L"/IM") == 0 && i + 1 < argc)
        {
            imageName = argv[++i];
            byImage = true;
        }
    }

    if (!byPid && !byImage)
    {
        wcerr << L"You must specify /PID or /IM.\n";
        return 1;
    }

    // ---------------- LOCAL MODE ----------------
    if (systemName.empty())
    {
        vector<DWORD> targets;

        if (byPid)
        {
            targets.push_back(pid);
        }
        else
        {
            targets = FindPidsByImageLocal(imageName);
            if (targets.empty())
            {
                wcerr << L"No process found matching image name: " << imageName << L"\n";
                return 1;
            }
        }

        auto all = SnapshotProcessesLocal();
        set<DWORD> finalTargets;

        for (DWORD t : targets)
        {
            finalTargets.insert(t);
            if (treeFlag)
                CollectChildrenRecursiveLocal(t, all, finalTargets);
        }

        vector<DWORD> ordered(finalTargets.begin(), finalTargets.end());
        std::reverse(ordered.begin(), ordered.end());

        bool anySuccess = false;
        for (DWORD targetPid : ordered)
        {
            bool ok = KillOneProcessLocal(targetPid);
            if (ok)
            {
                anySuccess = true;
                wcout << L"SUCCESS: Terminated PID " << targetPid;
                if (forceFlag) wcout << L" (forced)";
                if (treeFlag) wcout << L" (tree mode)";
                wcout << L"\n";
            }
            else
            {
                wcerr << L"ERROR: Could not terminate PID " << targetPid << L"\n";
            }
        }

        return anySuccess ? 0 : 1;
    }

    // ---------------- REMOTE MODE ----------------
    if (userName.empty())
    {
        wcerr << L"When using /S, please also supply /U <domain\\user>.\n";
        return 1;
    }

    if (password.empty())
    {
        wcout << L"Note: No /P supplied. Connection will use the current logon context or may fail if remote auth requires a password.\n";
    }

    ComInit com;
    HRESULT hr = com.Init();
    if (FAILED(hr))
    {
        wcerr << L"Failed to initialize COM/WMI. HRESULT=0x" << std::hex << hr << L"\n";
        return 1;
    }

    IWbemServices* pSvc = nullptr;
    hr = ConnectWmi(systemName, userName, password, &pSvc);
    if (FAILED(hr) || !pSvc)
    {
        wcerr << L"Failed to connect to remote system via WMI. HRESULT=0x" << std::hex << hr << L"\n";
        return 1;
    }

    vector<DWORD> targets;
    if (byPid)
    {
        targets.push_back(pid);
    }
    else
    {
        targets = FindPidsByImageRemote(pSvc, imageName);
        if (targets.empty())
        {
            wcerr << L"No process found on remote system matching image name: " << imageName << L"\n";
            pSvc->Release();
            return 1;
        }
    }

    vector<ProcessNode> allRemote;
    if (treeFlag)
        allRemote = SnapshotProcessesRemote(pSvc);

    set<DWORD> finalTargets;
    for (DWORD t : targets)
    {
        finalTargets.insert(t);
        if (treeFlag)
            CollectChildrenRecursiveRemote(t, allRemote, finalTargets);
    }

    vector<DWORD> ordered(finalTargets.begin(), finalTargets.end());
    std::reverse(ordered.begin(), ordered.end());

    bool anySuccess = false;
    for (DWORD targetPid : ordered)
    {
        bool ok = KillOneProcessRemote(pSvc, targetPid);
        if (ok)
        {
            anySuccess = true;
            wcout << L"SUCCESS: Remote terminated PID " << targetPid;
            if (forceFlag) wcout << L" (forced)";
            if (treeFlag) wcout << L" (tree mode)";
            wcout << L"\n";
        }
        else
        {
            wcerr << L"ERROR: Could not remote terminate PID " << targetPid << L"\n";
        }
    }

    pSvc->Release();
    return anySuccess ? 0 : 1;
}