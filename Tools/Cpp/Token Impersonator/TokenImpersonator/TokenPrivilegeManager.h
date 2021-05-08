#pragma once
#include <Windows.h>

typedef enum _TokenPrivilegeManagerReturnCodes TokenPrivilegeManagerReturnCodes;

class TokenPrivilegeManager
{
private:	
	HANDLE TokenHandle;
	PTOKEN_PRIVILEGES TokenPrivilegesP;
	void EnumTokenPrivileges();	

public:
	TokenPrivilegeManager(HANDLE TokenHandle);
	~TokenPrivilegeManager();
	PTOKEN_PRIVILEGES GetTokenPrivileges();
	BOOL IsPrivilegeEnabled(LPCSTR PrivilegeName);
	BOOL IsPrivilegePresent(LPCSTR PrivilegeName);
	BOOL DoesLuidMatch(LUID luid1, LUID luid2);
	BOOL ChangePrivilegeAttribute(LPCSTR PrivilegeName, BOOL Enable);
	BOOL ChangePrivilegeAttribute(LUID Luid, BOOL Enable);
	BOOL EnableAllPrivileges();
	BOOL DisableAllPrivileges();
};

