#include <Windows.h>
#include <iostream>
#include <thread>

using namespace std;

HANDLE NewProcStdoutWrH, NewProcStdoutRdH, NewProcStdinRdH, NewProcStdinWrH;

void StdoutHandler() {
	HANDLE CurrentProcStdout = GetStdHandle(STD_OUTPUT_HANDLE);
	WCHAR* buf = new WCHAR[2048];
	DWORD bytesRead = 0, bytesWritten = 0;
	while (true) {
		if (ReadFile(NewProcStdoutRdH, buf, 2048, &bytesRead, NULL)) {
			WriteFile(CurrentProcStdout, buf, bytesRead, &bytesWritten, NULL);
			ZeroMemory(buf, sizeof(buf));
		}
		else {
			if (GetLastError() == ERROR_BROKEN_PIPE) {
				break;
			}
		}
	}
}

void StdinHandler() {
	HANDLE CurrentProcStdin = GetStdHandle(STD_INPUT_HANDLE);
	WCHAR* buf = new WCHAR[2048];
	DWORD bytesRead = 0, bytesWritten = 0;
	while (true) {
		if (ReadFile(CurrentProcStdin, buf, 2048, &bytesRead, NULL)) {
			WriteFile(NewProcStdinWrH, buf, bytesRead, &bytesWritten, NULL);
			ZeroMemory(buf, sizeof(buf));
		}
		else {
			if (GetLastError() == ERROR_BROKEN_PIPE) {
				break;
			}
		}
	}
}

void main() {
	// Create security attributes for handle inheritance
	SECURITY_ATTRIBUTES SecurityAttributes;
	SecurityAttributes.bInheritHandle = true;
	SecurityAttributes.lpSecurityDescriptor = NULL;
	SecurityAttributes.nLength = sizeof(SECURITY_ATTRIBUTES);

	// Create pipes
	CreatePipe(&NewProcStdoutRdH, &NewProcStdoutWrH, &SecurityAttributes, 0);
	CreatePipe(&NewProcStdinRdH, &NewProcStdinWrH, &SecurityAttributes, 0);

	// Start handling threads
	thread StdoutHandlingThread(StdoutHandler), StdinHandlingThread(StdinHandler);

	// Create new process
	STARTUPINFO StartupInfo;
	PROCESS_INFORMATION ProcessInformation;
	ZeroMemory(&StartupInfo, sizeof(STARTUPINFO));
	ZeroMemory(&ProcessInformation, sizeof(PROCESS_INFORMATION));
	StartupInfo.cb = sizeof(STARTUPINFO);
	StartupInfo.hStdOutput = NewProcStdoutWrH;
	StartupInfo.hStdError = NewProcStdoutWrH;
	StartupInfo.hStdInput = NewProcStdinRdH;
	StartupInfo.dwFlags |= STARTF_USESTDHANDLES;
	
	LPWSTR NewProcess = (LPWSTR)L"C:\\Windows\\System32\\cmd.exe";
	if (!CreateProcess(NewProcess, NULL, NULL, NULL, true, CREATE_NEW_CONSOLE, NULL, NULL, &StartupInfo, &ProcessInformation)) {
		cout << "Error spawning new process: " << GetLastError() << endl;
		exit(0);
	}

	// Wait for threads
	StdoutHandlingThread.join();
	StdinHandlingThread.join();
}