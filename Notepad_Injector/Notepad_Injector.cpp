// Notepad_Injector.cpp : This file contains the 'main' function. Program execution begins and ends there.
//

#include "tchar.h"
#include <iostream>
#include <string>
#include <cstring>
#include <Windows.h>
#include <easyhook.h>

/*
	The steps are as follows:
	1) Get the process ID of the running Notepad process
	2) Attempt to inject the hook into the running Notepad process
*/


// Make sure we use the correct easy hook for our native architecture (in this case 64-bit Windows)
#if _WIN64
#pragma comment(lib, "EasyHook64.lib")
#else
#pragma comment(lib, "EasyHook32.lib")
#endif


using namespace std;

int _tmain(int argc, _TCHAR* argv[]) {

	// We will input the target process ID from the process ID of Notepad in Process Explorer
	DWORD processId;

	wcout << "Enter the target process ID: ";
	cin >> processId;

	// Point to our DLL hook
	// WCHAR* dllToInject = L"..\\x64\\Debug\\Notepad_Hook.dll";
	wprintf(L"Attempting to inject");

	// Inject into the process ID
	// freqOffset as the pass through data
	NTSTATUS nt = RhInjectLibrary(
		processId,
		0,
		EASYHOOK_INJECT_DEFAULT,
		NULL,
		(WCHAR*)L"..\\x64\\Debug\\Notepad_Hook.dll",
		NULL,
		0
	);

	// If our EasyHook inject command fails
	if (nt != 0) {

		printf("RhInjectLibrary failed with error code = %d\n", nt);
		PWCHAR err = RtlGetLastErrorString();
		wcout << err << "\n";

	}

	else
		wcout << L"Library injected successfully.\n";

	wcout << "Press Enter to exit";
	wstring input;
	getline(wcin, input);
	getline(wcin, input);



	return 0;

}