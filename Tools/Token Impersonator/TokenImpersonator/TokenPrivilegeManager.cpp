#include "TokenPrivilegeManager.h"

enum _TokenPrivilegeManagerReturnCodes {
	COULD_NOT_READ_TOKEN_PRIVILEGE,
	COULD_NOT_RESOLVE_PRIVILEGE_NAME_TO_LUID
};

TokenPrivilegeManager::TokenPrivilegeManager(HANDLE TokenHandle) {
	this->TokenHandle = TokenHandle;
	EnumTokenPrivileges();
}

TokenPrivilegeManager::~TokenPrivilegeManager() {
	HeapFree(GetProcessHeap(), HEAP_ZERO_MEMORY, TokenPrivilegesP);
}

BOOL TokenPrivilegeManager::DoesLuidMatch(LUID luid1, LUID luid2) {
	if ((luid1.HighPart == luid2.HighPart) && (luid1.LowPart == luid2.LowPart)) {
		return true;
	}
	else {
		return false;
	}
}

void TokenPrivilegeManager::EnumTokenPrivileges() {
	DWORD TokenPrivilegeBufferSize = 0;
	GetTokenInformation(TokenHandle, TokenPrivileges, NULL, 0, &TokenPrivilegeBufferSize);

	TokenPrivilegesP = (PTOKEN_PRIVILEGES)(HeapAlloc(GetProcessHeap(),
		HEAP_ZERO_MEMORY, TokenPrivilegeBufferSize));
	TokenPrivilegesP->PrivilegeCount = ((TokenPrivilegeBufferSize - sizeof(DWORD)) / sizeof(LUID_AND_ATTRIBUTES));
	if (!GetTokenInformation(TokenHandle, TokenPrivileges, TokenPrivilegesP, TokenPrivilegeBufferSize, &TokenPrivilegeBufferSize)) {
		SetLastError(TokenPrivilegeManagerReturnCodes::COULD_NOT_READ_TOKEN_PRIVILEGE);
	}
}

PTOKEN_PRIVILEGES TokenPrivilegeManager::GetTokenPrivileges() {
	return TokenPrivilegesP;
}

BOOL TokenPrivilegeManager::IsPrivilegePresent(LPCSTR PrivilegeName) {
	if (TokenPrivilegesP == NULL) {
		return false;
	}

	LUID RequiredLuid;
	if (!LookupPrivilegeValueA(NULL, PrivilegeName, &RequiredLuid)) {
		SetLastError(TokenPrivilegeManagerReturnCodes::COULD_NOT_RESOLVE_PRIVILEGE_NAME_TO_LUID);
		return false;
	}

	LUID_AND_ATTRIBUTES LuidAttributes;
	DWORD PrivilegeCount = TokenPrivilegesP->PrivilegeCount;
	for (int i = 0; i < PrivilegeCount; i++) {
		LuidAttributes = TokenPrivilegesP->Privileges[i];
		if (DoesLuidMatch(RequiredLuid, LuidAttributes.Luid)) {
			return true;
		}
	}
	return false;
}

BOOL TokenPrivilegeManager::IsPrivilegeEnabled(LPCSTR PrivilegeName) {
	if (TokenPrivilegesP == NULL) {
		return false;
	}
		
	LUID RequiredLuid;
	if (!LookupPrivilegeValueA(NULL, PrivilegeName, &RequiredLuid)) {
		SetLastError(TokenPrivilegeManagerReturnCodes::COULD_NOT_RESOLVE_PRIVILEGE_NAME_TO_LUID);
		return false;
	}

	LUID_AND_ATTRIBUTES LuidAttributes;
	DWORD PrivilegeCount = TokenPrivilegesP->PrivilegeCount;
	for (int i = 0; i < PrivilegeCount; i++) {
		LuidAttributes = TokenPrivilegesP->Privileges[i];
		if (DoesLuidMatch(RequiredLuid, LuidAttributes.Luid)) {
			if (LuidAttributes.Attributes != 0){
				return true;
			}
			else {
				return false;
			}
		}
	}

	return false;
}

BOOL TokenPrivilegeManager::ChangePrivilegeAttribute(LPCSTR PrivilegeName, BOOL Enable) {
	TOKEN_PRIVILEGES NewPrivilege;
	LUID PrivilegeLuid;
	if (!LookupPrivilegeValueA(NULL, PrivilegeName, &PrivilegeLuid)) {
		SetLastError(TokenPrivilegeManagerReturnCodes::COULD_NOT_RESOLVE_PRIVILEGE_NAME_TO_LUID);
		return false;
	}
	NewPrivilege.Privileges[0].Luid = PrivilegeLuid;
	if (Enable) {
		NewPrivilege.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
	}
	else {
		NewPrivilege.Privileges[0].Attributes = 0;
	}	
	if (!AdjustTokenPrivileges(TokenHandle, false, &NewPrivilege, NULL, NULL, NULL)) {
		return false;
	}
	else {
		return true;
	}
}

BOOL TokenPrivilegeManager::ChangePrivilegeAttribute(LUID Luid, BOOL Enable) {
	TOKEN_PRIVILEGES NewPrivilege;	
	NewPrivilege.Privileges[0].Luid = Luid;
	NewPrivilege.PrivilegeCount = 1;
	if (Enable) {
		NewPrivilege.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
	}
	else {
		NewPrivilege.Privileges[0].Attributes = 0;
	}
	if (!AdjustTokenPrivileges(TokenHandle, false, &NewPrivilege, NULL, NULL, NULL)) {		
		return false;
	}
	else {
		if (GetLastError() == ERROR_SUCCESS) {
			return true;
		}
		else {
			return false;
		}
	}
}

BOOL TokenPrivilegeManager::EnableAllPrivileges() {
	LUID Luid;
	BOOL result = true;	

	for (int i = 0; i < TokenPrivilegesP->PrivilegeCount; i++) {
		Luid = TokenPrivilegesP->Privileges[i].Luid;
		if (ChangePrivilegeAttribute(Luid, true)) {
			result = result & true;
		}
		else {
			result = result & false;
		}
	}
	return result;
}

BOOL TokenPrivilegeManager::DisableAllPrivileges() {
	if (!AdjustTokenPrivileges(TokenHandle, true, NULL, NULL, NULL, NULL)) {
		return false;
	}
	else {
		return true;
	}
}
