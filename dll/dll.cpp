#include <cstdlib>
#include <filesystem>
#include <string>
#include <cerrno>
#include <thread>
#include <cstdio>
#include <windows.h>
#include <processenv.h>
#include <libloaderapi.h>
#include <minwindef.h>
#include <fileapi.h>
#include <fcntl.h>
#include <winnt.h>
#include "ulog.h"

#include "dll.hpp"
#include "gui.hpp"
#include "patches.hpp"
#include "macros.hpp"
#include "libproxy.h"

namespace ioannes {

DllState *state;
HANDLE appThread;

void init_console(void) {
	ulog_output_level_set(ULOG_OUTPUT_STDOUT, ULOG_LEVEL_7);

	AllocConsole();
	SetConsoleTitleA("Ioannes Debug");

	HANDLE hConsole = GetStdHandle(STD_OUTPUT_HANDLE);
	state->fConsole = fdopen(_open_osfhandle((intptr_t)hConsole, _O_TEXT), "w");
	setvbuf(state->fConsole, NULL, _IONBF, 0);

	ulog_output_add_file(state->fConsole, ULOG_LEVEL_DEBUG);

#if LOGFILE
	auto logPath = state->tmpDir / "latest.log";
	ulog_info("Opening logfile: %s", logPath.string().c_str());
	state->logFile = fopen(logPath.string().c_str(), "w");
	setvbuf(state->logFile, NULL, _IONBF, 0);

	if (state->logFile == NULL) {
		ulog_error("Failed to open logfile: %s (errno: %d)", strerror(errno), errno);
	} else {
#if NDEBUG
		ulog_output_add_file(state->logFile, ULOG_LEVEL_DEBUG);
#else
		ulog_output_add_file(state->logFile, ULOG_LEVEL_TRACE);
#endif
	}
#endif
}

long unsigned int app_thread(void *) {
	ulog_info("Init app thread");

	init_console();
	ulog_info("mod base: %#x", state->dll);
	ulog_info("bin: %s", state->exePath.c_str());

	if (!init_patches()) CRIT("Failed to apply code patches");

	gui::init();

	return 0;
}

BOOL init(HINSTANCE hinstDLL) {
	state = new DllState;
	state->dll = hinstDLL;
	state->base = GetModuleHandle(NULL);
	GetModuleInformation(GetCurrentProcess(), state->base, &state->baseInfo, sizeof(state->baseInfo));

	TCHAR exePath[MAX_PATH + 1];
	GetModuleFileNameA(state->base, exePath, MAX_PATH);
	state->exePath = exePath;

	if (!state->exePath.ends_with("RocketLeague.exe")) return FALSE;

	TCHAR tmpDir[MAX_PATH + 1];
	GetTempPath(MAX_PATH, tmpDir);
	state->tmpDir = std::filesystem::path(tmpDir) / "ioannes";
	std::filesystem::create_directories(state->tmpDir);

	appThread = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)app_thread, NULL, 0, NULL);
	return TRUE;
}

void deinit(void) {
	ulog_debug("deinit");
	if (appThread != nullptr) {
		TerminateThread(appThread, 2);
		CloseHandle(appThread);
	}
}

}  // namespace ioannes

extern "C" {

DLL_EXPORT BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved) {
	switch (fdwReason) {
		case DLL_PROCESS_ATTACH:
			if (!ioannes::init(hinstDLL)) return FALSE;
			break;
		case DLL_PROCESS_DETACH:
			if (lpvReserved != nullptr) break;

			ioannes::deinit();
			break;
	}

	return TRUE;
}

}  // extern "C"
