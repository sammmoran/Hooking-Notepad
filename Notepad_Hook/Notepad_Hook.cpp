#include <tchar.h>
#include <string>
#include <iostream>
#include <Windows.h>
#include <winnt.h>
#include "pch.h"
#include <winternl.h>
#include <easyhook.h>




// Make sure we use the correct easy hook for our native architecture (in this case 64-bit Windows)
#if _WIN64
#pragma comment(lib, "EasyHook64.lib")
#else
#pragma comment(lib, "EasyHook32.lib")
#endif

// Now, we implement the hook of our choice
// This is the hook that will be run everytime we run the call for NtCreateFile
DWORD gFreqOffSet = 0;

NTSTATUS NtCreateFileHook(

	PHANDLE FileHandle,
	ACCESS_MASK DesiredAccess,
	POBJECT_ATTRIBUTES ObjectAttributes,
	PIO_STATUS_BLOCK IoStatusBlock,
	PLARGE_INTEGER AllocationSize,
	ULONG FileAttributes,
	ULONG ShareAccess,
	ULONG CreateDisposition,
	ULONG CreateOptions,
	PVOID EaBuffer,
	ULONG EaLength
);


NTSTATUS NtCreateFileHook(

	PHANDLE FileHandle,
	ACCESS_MASK DesiredAccess,
	POBJECT_ATTRIBUTES ObjectAttributes,
	PIO_STATUS_BLOCK IoStatusBlock,
	PLARGE_INTEGER AllocationSize,
	ULONG FileAttributes,
	ULONG ShareAccess,
	ULONG CreateDisposition,
	ULONG CreateOptions,
	PVOID EaBuffer,
	ULONG EaLength
) {

	// This is the functionality that we want our hook to run. This is the endgame for our malware. We want this message 
	// box to run whenever the program calls the NtCreateFile import.
	MessageBox(GetActiveWindow(), (LPCWSTR)ObjectAttributes->ObjectName->Buffer, (LPCWSTR)L"Object Name", MB_OK);


	// Once the above functionality has completed, we then allow the original program flow to continue by redirecting to 
	// the original DLL import call. This ensures that the Notepad application won't crash.
	return NtCreateFile(
		FileHandle,
		DesiredAccess,
		ObjectAttributes,
		IoStatusBlock,
		AllocationSize,
		FileAttributes,
		ShareAccess,
		CreateDisposition,
		CreateOptions,
		EaBuffer,
		EaLength
	);

}

// Notepad_Injector is going to look for this export.
// This export is going to be called by Notepad_Injector. (see call to RhInjectLibrary in Notepad_Injector.cpp)
// The actual implementation of this function is right below.
extern "C" void __declspec(dllexport) __stdcall NativeInjectionEntryPoint(REMOTE_ENTRY_INFO* inRemoteInfo);


// We now get to the actual hook functionality of our choice
// This code will actually install the EasyHook hook and sets the thread for the hook to monitor
void __stdcall NativeInjectionEntryPoint(REMOTE_ENTRY_INFO* inRemoteInfo) {

	// Perform hooking
	HOOK_TRACE_INFO hHook = { NULL }; // This will be used to keep track of our hook object

	NTSTATUS result = LhInstallHook(

		GetProcAddress(GetModuleHandle(TEXT("ntdll")), "NtCreateFile"),
		NtCreateFileHook,
		NULL,
		&hHook);

	// Our Install function above will return a result.
	// If the install failed
	if (FAILED(result)) {

		MessageBox(GetActiveWindow(), (LPCWSTR)RtlGetLastErrorString(), (LPCWSTR)L"Failed to install hook", MB_OK);

	}

	// If the threadId in the ACL is set to 0,
	// then internally Easyhook uses GetCurrentThread()
	ULONG ACLEntries[1] = { 0 };

	// Disable the hook for the provided threadIds, enable for all others
	LhSetExclusiveACL(ACLEntries, 1, &hHook);

	return;
}

void __stdcall 