// Custom
#include "sandbox.h"

// Windows
#include <Windows.h>
#include <Security.h>
#include <secext.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdbool.h>

#pragma comment(lib, "Secur32.lib")  // Need this to use GetUserNameExA

BOOL checkDomainName(void) {
	CHAR domainBuff[1024];
	DWORD domainNameLen = sizeof(domainBuff);

	GetComputerNameExA(ComputerNameDnsDomain, domainBuff, &domainNameLen);
	
	//printf("sup: %s\n", domainBuff);

	if (domainNameLen > 0) {
		return TRUE;
	}

	return FALSE;
}