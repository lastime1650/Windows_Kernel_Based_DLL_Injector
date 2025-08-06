#pragma warning(disable: 4996)
#include "HWBP.h"

#include "api.h"

NTSTATUS PID_to_HANDLE2(
	_In_ HANDLE ProcessId,
	_Out_ HANDLE* ProcessHandle
);

NTSTATUS Set_Hardware_BreakPoint(
	HANDLE ProcessId,
	PUCHAR TargetAddress
) {

	
	ULONG32 bufferSize = 0; // Initial buffer size
	PUCHAR buffer = NULL;
	NTSTATUS status = STATUS_UNSUCCESSFUL;

	HANDLE ProcessHandle = NULL;
	PID_to_HANDLE2(
		ProcessId, // Target Process ID
		&ProcessHandle // Output Process Handle
	);

	PEPROCESS Process = NULL;
	PsLookupProcessByProcessId(ProcessId, &Process);

	BOOLEAN is64bit = (PsGetProcessWow64Process(Process) == NULL);

	while (ZwQuerySystemInformation(SystemProcessInformation, buffer, bufferSize, &(ULONG)bufferSize) == STATUS_INFO_LENGTH_MISMATCH) {
		if (buffer == NULL) {
			buffer = ExAllocatePoolWithTag(NonPagedPool, bufferSize, 'QRPS'); // QueRyProceSs
			if (buffer == NULL) {
				DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, " �޸� �Ҵ� ���� \n");
				status = STATUS_INSUFFICIENT_RESOURCES;
				goto EXIT1;
			}
		}
	}


	PSYSTEM_PROCESS_INFORMATION processInfo = (PSYSTEM_PROCESS_INFORMATION)buffer;
	if (!processInfo)
	{
		DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, " �޸� �Ҵ� ���� \n");
		status = STATUS_UNSUCCESSFUL;
		goto EXIT2;
	}
		

	while (processInfo) {
		if (processInfo->UniqueProcessId == ProcessId) {
			// Found the target process

			// Let's Find Process Threads in loop
			// And then Set Hardware Breakpoint
			PSYSTEM_THREAD_INFORMATION threadInfo = processInfo->Threads;
			for (ULONG i = 0; i < processInfo->NumberOfThreads; i++) {

				HANDLE ThreadID = threadInfo[i].ClientId.UniqueThread; // get thread id

				// Get PETHREAD
				PETHREAD Thread = NULL;
				if (PsLookupThreadByThreadId(ThreadID, &Thread) != STATUS_SUCCESS) {
					DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, " ������ ��ü ��� ���� \n");
					threadInfo++;
					continue;
				}

				// Get Thread Handle
				HANDLE ThreadHandle = NULL;
				status = ObOpenObjectByPointer(
					Thread,
					OBJ_KERNEL_HANDLE,
					NULL,
					THREAD_ALL_ACCESS,
					*PsThreadType,
					KernelMode,
					&ThreadHandle
				);
				if (!NT_SUCCESS(status)) {
					DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, " ������ �ڵ� ��� ���� \n");
					ObDereferenceObject(Thread); // Dereference PETHREAD
					threadInfo++;
					continue;
				}

				/*
				
					Get Thread Context ( current ) 
				
				*/
				

				KAPC_STATE APC_STATE = { 0, };	
				KeStackAttachProcess(Process, &APC_STATE); // Attach to the target process context

				PCONTEXT context_USERMODE = NULL;
				
				SIZE_T contextSize = sizeof(CONTEXT);
				ZwAllocateVirtualMemory(
					ProcessHandle,
					&context_USERMODE,
					0,
					&contextSize,
					MEM_COMMIT,
					PAGE_READWRITE
				);
				memset(context_USERMODE, 0, contextSize); // Initialize context to zero
				context_USERMODE->ContextFlags = CONTEXT_ALL;

				status = PsGetContextThread(Thread, context_USERMODE, UserMode);
				if (!NT_SUCCESS(status)) {
					KeUnstackDetachProcess(&APC_STATE); // Detach from the target process context

					DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, " ������ ���ؽ�Ʈ ��� ���� \n");
					ObCloseHandle(ThreadHandle, KernelMode);
					ObDereferenceObject(Thread); // Dereference PETHREAD
					threadInfo++;
					continue;
				}





				if (!is64bit) {
					// 32 bit
					// Set Hardware Breakpoint
					context_USERMODE->Dr0 = (ULONG64)TargetAddress; // Example address, replace with actual target address
					context_USERMODE->Dr7 |= (1 << 0);
					context_USERMODE->Dr7 |= (3 << (16 + (0 * 4)));
					context_USERMODE->Dr7 |= (3 << (18 + (0 * 4)));

					/* Dr1: Execute( 00 ) - 4����Ʈ���� (�������� ũ�����)*/
					context_USERMODE->Dr1 = (ULONG64)TargetAddress;
					context_USERMODE->Dr7 |= (1 << 2);
					context_USERMODE->Dr7 |= (0 << (16 + 1 * 4)); // Execute
					context_USERMODE->Dr7 |= (3 << (18 + 1 * 4)); // ũ��(4����Ʈ) 
				}
				else {
					// 64bit
					/* Dr2: Read/Write( 11 ) - 8����Ʈ���� */
					context_USERMODE->Dr2 = (ULONG64)TargetAddress;
					context_USERMODE->Dr7 |= (1 << 4);
					context_USERMODE->Dr7 |= (3 << (16 + 2 * 4)); // ReadWrite
					context_USERMODE->Dr7 |= (2 << (18 + 2 * 4)); // ũ�� 8����Ʈ


					/* Dr3: Execute( 00 ) - 8����Ʈ���� */
					context_USERMODE->Dr3 = (ULONG64)TargetAddress;
					context_USERMODE->Dr7 |= (1 << 6);
					context_USERMODE->Dr7 |= (0 << (16 + 3 * 4));  // Execute
					context_USERMODE->Dr7 |= (2 << (18 + 3 * 4));  // ũ�� 8����Ʈ
				}

				CONTEXT


				
				
				status = PsSetContextThread(Thread, context_USERMODE, UserMode);
				if (!NT_SUCCESS(status)) {
					KeUnstackDetachProcess(&APC_STATE); // Detach from the target process context

					DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, " ������ ���ؽ�Ʈ ��� ���� \n");
					ObCloseHandle(ThreadHandle, KernelMode);
					ObDereferenceObject(Thread); // Dereference PETHREAD
					continue;
				}

				KeUnstackDetachProcess(&APC_STATE); // Detach from the target process context


				ObDereferenceObject(Thread); // Dereference PETHREAD
				threadInfo++;


				DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, " ���ؽ�Ʈ ���� \n");
			}

			break;
		}
		processInfo = (PSYSTEM_PROCESS_INFORMATION)((PUCHAR)processInfo + processInfo->NextEntryOffset);
	}


EXIT2:
	ExFreePoolWithTag(buffer, 'QRPS');
EXIT1:
	ObDereferenceObject(Process);
	return status;
}




NTSTATUS PID_to_HANDLE2(
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