#pragma once

#include "stdafx.h"

class UserOperate{
	public:
		UserOperate();

		BOOL GetUserPass(CHAR*, CHAR*);

		BOOL UserCreate(VOID);

		BOOL UserDel(VOID);

		~UserOperate();
	private:
		CHAR username[256];
		CHAR userpass[256];
};

