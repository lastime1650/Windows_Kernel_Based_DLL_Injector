#include "dll_inject.h"

#include "api.h"

NTSTATUS Kernel_Copy_2_Virtual(
	_In_ HANDLE ProcessId,

	_In_ PUCHAR KernelDataAddress,
	_In_ SIZE_T DataSize,

	_Out_ PUCHAR* VirtualDataAddress // VirtualAlloc으로 할당된 메모리 주소
);

NTSTATUS Dll_API_Address_Search(
	HANDLE Processid,

	PWCH Dll_Name, // Dll Name
	PCHAR Api_Name, // API Name

	PUCHAR* Dll_Base_VirtualAddress, // Dll Base Address
	PUCHAR* API_VirtualAddress
) {
	NTSTATUS status = STATUS_UNSUCCESSFUL;

	if (
		!Dll_Name ||
		!Api_Name ||
		!API_VirtualAddress ||
		!Dll_Base_VirtualAddress) {
		return STATUS_INVALID_PARAMETER;
	}

	/*
	==================================================================
	Find DLL ! From TargetProcess

	** Attention
	* should be know the target process 32 or 64 bit !!!  ( for PE parsing )
	* If return the API Address, it is a VIrtual Address! Not Kernel Address... !!!@@#$!@

	STEP 1) Looking for the Eprocess from PID

	STEP 2) Attach to UserMode target process Context

	STEP 3) Get PEB

	STEP 4) Get Dll informations from LDR ..

	STEP 5) Get Api Address from Dll Base Address

	==================================================================
	*/



	// STEP 1
	PEPROCESS targetProcess = NULL;
	status = PsLookupProcessByProcessId(Processid, &targetProcess);
	if (!NT_SUCCESS(status))
		goto EXIT0;

	// STEP 2
	KAPC_STATE APC_STATE;
	KeStackAttachProcess(targetProcess, &APC_STATE);

	// STEP 3
	PPEB Peb = PsGetProcessPeb(targetProcess);
	if (!Peb) {
		status = STATUS_UNSUCCESSFUL;
		goto EXIT2;
	}

	// find the dll
	if (Peb->Ldr && Peb->Ldr->InMemoryOrderModuleList.Flink) {

		PLIST_ENTRY ListHead = &Peb->Ldr->InMemoryOrderModuleList;
		PLIST_ENTRY CurrentEntry = ListHead->Flink;

		UNICODE_STRING moduleName;
		RtlInitUnicodeString(&moduleName, Dll_Name);

		// STEP 4
		while (CurrentEntry != ListHead) {

			PLDR_DATA_TABLE_ENTRY LdrEntry = CONTAINING_RECORD(CurrentEntry, LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks);

			// Compare the Dll Name
			if (RtlEqualUnicodeString(&LdrEntry->BaseDllName, &moduleName, TRUE)) {
				// Found the Dll
				*Dll_Base_VirtualAddress = LdrEntry->DllBase; // Set Dll Base Address

				// STEP 5
				PIMAGE_DOS_HEADER__ DllDosHeader = (PIMAGE_DOS_HEADER__)LdrEntry->DllBase;
				if (DllDosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
					DbgPrintEx(
						DPFLTR_IHVDRIVER_ID,
						DPFLTR_ERROR_LEVEL,
						" Invalid Dll Dos Header Signature %d \n", Processid
					);
					status = STATUS_INVALID_IMAGE_FORMAT;
					goto EXIT2;
				}

				PIMAGE_EXPORT_DIRECTORY ExportDir = NULL;




				// 64bit
				PIMAGE_NT_HEADERS64__ NtHeaders64 = (PIMAGE_NT_HEADERS64__)((PUCHAR)LdrEntry->DllBase + DllDosHeader->e_lfanew);

				if (
					NtHeaders64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress
					) {
					ExportDir = (PIMAGE_EXPORT_DIRECTORY)((PUCHAR)LdrEntry->DllBase + NtHeaders64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);

				}

				

				if (!ExportDir) {
					DbgPrintEx(
						DPFLTR_IHVDRIVER_ID,
						DPFLTR_ERROR_LEVEL,
						" No Export APIS \n"
					);
					status = STATUS_NOT_FOUND;
					goto EXIT2;
				}

				PULONG pAddressOfFunctions = (PULONG)((PUCHAR)LdrEntry->DllBase + ExportDir->AddressOfFunctions);
				PULONG pAddressOfNames = (PULONG)((PUCHAR)LdrEntry->DllBase + ExportDir->AddressOfNames);
				PUSHORT  pAddressOfNameOrdinals = (PUSHORT)((PUCHAR)LdrEntry->DllBase + ExportDir->AddressOfNameOrdinals);

				// 2. Export된 모든 함수 이름을 순회합니다.
				for (ULONG i = 0; i < ExportDir->NumberOfNames; i++) {

					PUCHAR Functionname = ((PUCHAR)LdrEntry->DllBase + pAddressOfNames[i]);

					USHORT Oridnal = pAddressOfNameOrdinals[i];

					ULONG FunctionRva = pAddressOfFunctions[Oridnal];

					PUCHAR FunctionAddress = ((PUCHAR)LdrEntry->DllBase + FunctionRva);

					// Compare API Name
					if (strcmp((PCHAR)Functionname, Api_Name) != 0) {
						continue; // Skip if not match
					}

					// Found the API

					DbgPrintEx(
						DPFLTR_IHVDRIVER_ID,
						DPFLTR_ERROR_LEVEL,
						"성공: API '%s'를 찾았습니다. 주소: %p \n",
						Functionname,
						FunctionAddress
					);

					*API_VirtualAddress = FunctionAddress;

					goto EXIT2;
				}

				break;
			}

			CurrentEntry = CurrentEntry->Flink; // Move to next entry


		}


	}
	else {
		DbgPrintEx(
			DPFLTR_IHVDRIVER_ID,
			DPFLTR_ERROR_LEVEL,
			" Can't found LDR from PEB %d \n", Processid
		);
	}




EXIT2:
	KeUnstackDetachProcess(&APC_STATE);
	ObDereferenceObject(targetProcess);
EXIT0:
	return status;
}


NTSTATUS PID_to_HANDLE(
	_In_ HANDLE ProcessId,
	_Out_ HANDLE* ProcessHandle
) {
	if (!ProcessHandle)
		return STATUS_INVALID_PARAMETER;

	NTSTATUS status = STATUS_SUCCESS;

	PEPROCESS eprocess = NULL;
	status = PsLookupProcessByProcessId(ProcessId, &eprocess);
	if (!NT_SUCCESS(status)) {
		return status; // Failed to get process object
	}
	
	status = ObOpenObjectByPointer(
		eprocess,
		OBJ_KERNEL_HANDLE,
		NULL,
		PROCESS_ALL_ACCESS, // Adjust access rights as needed
		*PsProcessType,
		KernelMode,
		ProcessHandle
	);
	if (!NT_SUCCESS(status)) {
		ObDereferenceObject(eprocess);
		return status; // Failed to get process object
	}

	return STATUS_SUCCESS;
}

NTSTATUS DLL_Inject(

	_In_ HANDLE ProcessId, // Target Process ID

	_In_ PCHAR Injection_Dll_PATH // Hacking Dll Path
) {
	NTSTATUS status = STATUS_UNSUCCESSFUL;

	PUCHAR Dll_Base_VirtualAddress = NULL;
	PUCHAR API_VirtualAddress = NULL;

	status = Dll_API_Address_Search(
		ProcessId,
		L"kernel32.dll", // Dll Name
		"LoadLibraryA", // API Name
		&Dll_Base_VirtualAddress, // Dll Base Address
		&API_VirtualAddress // API Address
	);
	if (!NT_SUCCESS(status)) {
		return status;
	}

	HANDLE ProcessHandle;
	status = PID_to_HANDLE(ProcessId, &ProcessHandle);
	if (!NT_SUCCESS(status)) {
		return status; // Failed to get process handle
	}

	PUCHAR Dll_Path_VirtualAddress = NULL; // Virtual Address to store the allocated memory
	Kernel_Copy_2_Virtual(
		ProcessId, // Target Process ID
		(PUCHAR)Injection_Dll_PATH, // Kernel Address ( User Mode Address )
		strlen(Injection_Dll_PATH) + 1, // Size of data to copy ( +1 for null terminator )
		&Dll_Path_VirtualAddress // Virtual Address to store the allocated memory
	);


	// Dll Inject START
	HANDLE returned_thread_id = 0;
	status = RtlCreateUserThread(
		ProcessHandle, // Target Process REAL Handle
		NULL, // Security Descriptor
		FALSE, // Create Suspended
		0, // ZeroBits
		0, // Stack Zero
		0, // Stack Zero
		API_VirtualAddress, // LoadLibraryA Address
		Dll_Path_VirtualAddress, // Dll Path to Inject
		&returned_thread_id, // Thread Handle ( NULL )
		NULL // Client ID ( NULL )

	);

	DbgPrintEx(
		DPFLTR_IHVDRIVER_ID,
		DPFLTR_ERROR_LEVEL,
		" RtlCreateUserThread 호출됨 \n"
	);

	return status;

}





NTSTATUS VirtualAllocate(
	_In_ HANDLE ProcessHandle,
	_In_ SIZE_T Size,

	_Inout_ PUCHAR* StartAddress
) {
	if (!StartAddress)
		return STATUS_INVALID_PARAMETER;

	NTSTATUS status = ZwAllocateVirtualMemory(
		ProcessHandle,
		(PVOID*)StartAddress,
		0,
		&Size,
		MEM_COMMIT,
		PAGE_READWRITE
	);

	if (!NT_SUCCESS(status)) {
		*StartAddress = NULL; // FAILED
		return status;
	}

	return status;
}

NTSTATUS Kernel_Copy_2_Virtual(
	_In_ HANDLE ProcessId,

	_In_ PUCHAR KernelDataAddress,
	_In_ SIZE_T DataSize,

	_Out_ PUCHAR* VirtualDataAddress // VirtualAlloc으로 할당된 메모리 주소
) {
	if (!KernelDataAddress || !VirtualDataAddress)
		return STATUS_INVALID_PARAMETER;

	PEPROCESS process = NULL;
	HANDLE ProcessHandle = NULL;

	PsLookupProcessByProcessId(ProcessId, &process);

	PID_to_HANDLE(
		ProcessId, // Target Process ID
		&ProcessHandle // Output Process Handle
	);





	// Alloc to Virtual
	PUCHAR AllocatedVirtualAddress = NULL;
	NTSTATUS status = VirtualAllocate(
		ProcessHandle, // Target Process Handle
		DataSize, // Size of data to allocate
		&AllocatedVirtualAddress // Address to store the allocated memory
	);
	if (!NT_SUCCESS(status)) {
		ObDereferenceObject(process);
		return status; // Failed to allocate virtual memory
	}





	PEPROCESS systemprocess = PsGetCurrentProcess(); // SYSTEM.exe ( if not USERMODE context ) 

	SIZE_T return_size = 0;
	status = MmCopyVirtualMemory(


		systemprocess, // Source Process (SYSTEM)
		KernelDataAddress, // Source Address (User Mode Address)

		process, // Target Process (Target Process Object)
		AllocatedVirtualAddress, // Target Address (Kernel Mode Address)

		DataSize, // Size of data to copy
		KernelMode, // Source mode
		&return_size // Status

	);

	*VirtualDataAddress = AllocatedVirtualAddress; // Set the allocated virtual address

	ObDereferenceObject(process);
	return status;
}

