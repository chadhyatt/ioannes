#pragma once
#include <cstdio>
#include <string>
#include <filesystem>
#include <windows.h>
#include <psapi.h>

namespace ioannes {

typedef struct {   // DllState
	HMODULE base;  // Main RL handle
	MODULEINFO baseInfo;
	std::string exePath;
	HINSTANCE dll;

	HANDLE hConsole;
	int fdConsole;
	FILE *fConsole;

	std::filesystem::path tmpDir;
#if LOGFILE
	FILE *logFile;
#endif
} DllState;

extern DllState *state;

}  // namespace ioannes
