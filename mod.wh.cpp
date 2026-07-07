// ==WindhawkMod==
// @id             pivotlink-browser-router
// @name           PivotLink: Browser Router
// @description    Lightweight link redirection tool with an intuitive 5-tier ranked configuration layout.
// @version        1.0
// @author         gauthumj
// @github         https://github.com/gauthumj
// @include        *
// @compilerOptions -lshell32
// @license        MIT
// ==/WindhawkMod==

// ==WindhawkModReadme==
/*
Ever had a browser open already and Windows opened a Discord/Slack link in your default browser by launching it from scratch? Now it won't.

## What It Does

PivotLink intercepts outgoing URL launches system-wide and redirects them to whichever browser you already have running, based on a 5-tier priority list you configure. Instead of Windows blindly spawning your default browser, PivotLink checks what's actually open and sends the link there.

## How It Works

- Hooks `ShellExecuteW` and `ShellExecuteExW` to catch URL opens before they reach the OS default handler.
- Scans the running process list using a single-pass converging search to find the highest-priority browser that's already active.
- If a match is found, the link is silently rerouted to that browser. If none of your ranked browsers are running, the call falls through to normal Windows behavior.
- Circular routing is prevented — if you're already inside the target browser, the hook steps aside.

## Configuration

- **Priority 1–5 Browsers**: Rank up to five browsers by executable name (e.g. `brave.exe`, `firefox.exe`). The first one found running wins.

## Notes

- The mod skips Session 0 processes (system services) automatically.
- A thread-local guard prevents recursive hook calls during redirection.
*/
// ==/WindhawkModReadme==

// ==WindhawkModSettings==
/*
- browser1: "brave.exe"
  $name: Priority 1 Browser (Highest)
  $description: Your primary choice for link redirection (e.g., brave.exe). Leave blank to skip.
- browser2: "firefox.exe"
  $name: Priority 2 Browser
  $description: Second choice browser if Priority 1 is not running. Leave blank to skip.
- browser3: "chrome.exe"
  $name: Priority 3 Browser
  $description: Third choice browser if higher priorities are closed. Leave blank to skip.
- browser4: "msedge.exe"
  $name: Priority 4 Browser
  $description: Fourth choice browser fallback. Leave blank to skip.
- browser5: ""
  $name: Priority 5 Browser (Lowest)
  $description: Fifth choice browser fallback. Leave blank to skip.
*/
// ==/WindhawkModSettings==

#include <windows.h>
#include <shellapi.h>
#include <tlhelp32.h>
#include <windhawk_utils.h>
#include <mutex>
#include <vector>
#include <string>

std::mutex g_settingsMutex;
std::vector<std::wstring> g_priorityBrowsers;
thread_local bool t_inHook = false; 

std::wstring TrimString(const std::wstring& str) {
    size_t first = str.find_first_not_of(L" \t\r\n");
    if (first == std::wstring::npos) return L"";
    size_t last = str.find_last_not_of(L" \t\r\n");
    return str.substr(first, (last - first + 1));
}

// Checks if a process has at least one visible top-level window (i.e., is truly "open")
struct VisibleWindowCheck {
    DWORD processId;
    bool found;
};

static BOOL CALLBACK CheckVisibleWindowProc(HWND hwnd, LPARAM lParam) {
    VisibleWindowCheck* check = reinterpret_cast<VisibleWindowCheck*>(lParam);
    DWORD pid = 0;
    GetWindowThreadProcessId(hwnd, &pid);
    if (pid != check->processId) return TRUE;

    BOOL visible = IsWindowVisible(hwnd);
    LONG_PTR style = GetWindowLongPtrW(hwnd, GWL_STYLE);
    LONG_PTR exStyle = GetWindowLongPtrW(hwnd, GWL_EXSTYLE);
    int titleLen = GetWindowTextLengthW(hwnd);
    WCHAR title[256] = {};
    GetWindowTextW(hwnd, title, 256);
    RECT rect = {};
    GetWindowRect(hwnd, &rect);

    Wh_Log(L"  PID %u hwnd=%p visible=%d minimized=%d toolWnd=%d title(%d)=\"%s\" rect=[%d,%d,%d,%d]",
        pid, hwnd, visible,
        (style & WS_MINIMIZE) ? 1 : 0,
        (exStyle & WS_EX_TOOLWINDOW) ? 1 : 0,
        titleLen, title,
        rect.left, rect.top, rect.right, rect.bottom);

    if (!visible) {
        Wh_Log(L"  -> Skipped: not visible");
        return TRUE;
    }
    if (exStyle & WS_EX_TOOLWINDOW) {
        Wh_Log(L"  -> Skipped: tool window");
        return TRUE;
    }
    if (titleLen == 0) {
        Wh_Log(L"  -> Skipped: no title");
        return TRUE;
    }
    if ((rect.right - rect.left) <= 1 || (rect.bottom - rect.top) <= 1) {
        Wh_Log(L"  -> Skipped: rect too small");
        return TRUE;
    }

    Wh_Log(L"  -> MATCH: valid browser window");
    check->found = true;
    return FALSE;
}

static bool HasVisibleWindow(DWORD processId) {
    Wh_Log(L"HasVisibleWindow checking PID %u", processId);
    VisibleWindowCheck check = { processId, false };
    EnumWindows(CheckVisibleWindowProc, reinterpret_cast<LPARAM>(&check));
    Wh_Log(L"HasVisibleWindow PID %u result: %s", processId, check.found ? L"FOUND" : L"NOT FOUND");
    return check.found;
}

// Finds the highest-priority browser that is actively open (has a visible window).
// Background-only processes (e.g., Edge service workers) are ignored.
std::wstring GetHighestPriorityRunningBrowser() {
    std::vector<std::wstring> browsers;
    {
        std::lock_guard<std::mutex> lock(g_settingsMutex);
        browsers = g_priorityBrowsers;
    }

    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnap == INVALID_HANDLE_VALUE) return L"";

    PROCESSENTRY32W pe;
    pe.dwSize = sizeof(pe);
    
    std::vector<std::vector<DWORD>> browserPids(browsers.size());

    if (Process32FirstW(hSnap, &pe)) {
        do {
            for (size_t i = 0; i < browsers.size(); ++i) {
                if (_wcsicmp(pe.szExeFile, browsers[i].c_str()) == 0) {
                    browserPids[i].push_back(pe.th32ProcessID);
                    break;
                }
            }
        } while (Process32NextW(hSnap, &pe));
    }
    CloseHandle(hSnap);

    for (size_t i = 0; i < browsers.size(); ++i) {
        Wh_Log(L"Checking browser[%d]: %s (%d PIDs found)", (int)i, browsers[i].c_str(), (int)browserPids[i].size());
        for (DWORD pid : browserPids[i]) {
            if (HasVisibleWindow(pid)) {
                Wh_Log(L"Winner: %s (PID %u)", browsers[i].c_str(), pid);
                return browsers[i];
            }
        }
    }
    
    Wh_Log(L"No running browser found");
    return L"";
}

std::wstring GetCurrentProcessName() {
    WCHAR path[MAX_PATH];
    if (GetModuleFileNameW(NULL, path, MAX_PATH)) {
        std::wstring sPath(path);
        size_t pos = sPath.find_last_of(L"\\/");
        if (pos != std::wstring::npos) return sPath.substr(pos + 1);
        return sPath;
    }
    return L"UNKNOWN";
}

void LoadSettings() {
    const WCHAR* browserKeys[] = { L"browser1", L"browser2", L"browser3", L"browser4", L"browser5" };

    std::vector<std::wstring> browsers;
    for (int i = 0; i < 5; ++i) {
        auto setting = WindhawkUtils::StringSetting::make(browserKeys[i]);
        std::wstring trimmed = TrimString(setting.get());
        if (!trimmed.empty()) {
            browsers.push_back(trimmed);
        }
    }

    std::lock_guard<std::mutex> lock(g_settingsMutex);
    g_priorityBrowsers = std::move(browsers);
}

using ShellExecuteExW_t = decltype(&ShellExecuteExW);
ShellExecuteExW_t ShellExecuteExW_Original;

bool RouteLinkIfNecessary(const WCHAR* lpFile, const WCHAR* lpVerb, const WCHAR* lpParameters, int nShow) {
    if (!lpFile || t_inHook) return false;

    // Only redirect default (NULL) or "open" verbs
    if (lpVerb && _wcsicmp(lpVerb, L"open") != 0) return false;

    bool isLink = (_wcsnicmp(lpFile, L"http://", 7) == 0 || _wcsnicmp(lpFile, L"https://", 8) == 0);
    if (!isLink) return false;

    std::wstring currentProc = GetCurrentProcessName();
    Wh_Log(L"RouteLinkIfNecessary: URL=%s from=%s", lpFile, currentProc.c_str());
    std::wstring targetBrowser = GetHighestPriorityRunningBrowser();
    Wh_Log(L"Target browser result: \"%s\"", targetBrowser.c_str());

    if (!targetBrowser.empty()) {
        // Prevent circular routing inside the target browser
        if (_wcsicmp(currentProc.c_str(), targetBrowser.c_str()) == 0) {
            return false;
        }

        std::wstring cleanUrl = lpFile;
        if (cleanUrl.length() >= 2 && cleanUrl.front() == L'"' && cleanUrl.back() == L'"') {
            cleanUrl = cleanUrl.substr(1, cleanUrl.length() - 2);
        }

        Wh_Log(L"Routing link to: %s", targetBrowser.c_str());

        SHELLEXECUTEINFOW sei = { sizeof(sei) };
        sei.fMask = SEE_MASK_FLAG_NO_UI;
        sei.lpFile = targetBrowser.c_str();         
        sei.lpParameters = cleanUrl.c_str(); 
        sei.nShow = nShow;
        
        t_inHook = true;
        BOOL success = ShellExecuteExW_Original(&sei);
        t_inHook = false;

        if (success) return true;
    }
    return false;
}

BOOL WINAPI ShellExecuteExW_Hook(LPSHELLEXECUTEINFOW pExecInfo) {
    if (pExecInfo && pExecInfo->lpFile) {
        if (RouteLinkIfNecessary(pExecInfo->lpFile, pExecInfo->lpVerb, pExecInfo->lpParameters, pExecInfo->nShow)) {
            pExecInfo->hInstApp = (HINSTANCE)33; 
            return TRUE;
        }
    }
    return ShellExecuteExW_Original(pExecInfo);
}

using ShellExecuteW_t = decltype(&ShellExecuteW);
ShellExecuteW_t ShellExecuteW_Original;

HINSTANCE WINAPI ShellExecuteW_Hook(HWND hwnd, LPCWSTR lpOperation, LPCWSTR lpFile, LPCWSTR lpParameters, LPCWSTR lpDirectory, INT nShow) {
    if (RouteLinkIfNecessary(lpFile, lpOperation, lpParameters, nShow)) {
        return (HINSTANCE)33;
    }
    return ShellExecuteW_Original(hwnd, lpOperation, lpFile, lpParameters, lpDirectory, nShow);
}

BOOL Wh_ModInit() {
    // Session 0 bypass
    DWORD dwSessionId = 0;
    if (ProcessIdToSessionId(GetCurrentProcessId(), &dwSessionId) && dwSessionId == 0) {
        return FALSE; 
    }

    LoadSettings();

    WindhawkUtils::SetFunctionHook(ShellExecuteExW, ShellExecuteExW_Hook, &ShellExecuteExW_Original);
    WindhawkUtils::SetFunctionHook(ShellExecuteW, ShellExecuteW_Hook, &ShellExecuteW_Original);

    return TRUE;
}

void Wh_ModUninit() {
}

void Wh_ModSettingsChanged() {
    LoadSettings();
}