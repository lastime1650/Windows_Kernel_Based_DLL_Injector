#include <ntifs.h>

#include "dll_inject.h"
#include "HWBP.h"

NTSTATUS
DriverEntry(
	_In_ PDRIVER_OBJECT DriverObject,
	_In_ PUNICODE_STRING RegistryPath
) {
	UNREFERENCED_PARAMETER(DriverObject);
	UNREFERENCED_PARAMETER(RegistryPath);

	NTSTATUS status;

	status = DLL_Inject(
		(HANDLE)8296,
		"C:\\GameHackDLL.dll"
	);

	status = Set_Hardware_BreakPoint(
		(HANDLE)8296, // Process ID
		(PUCHAR)0x303EF3F7C0 // Target Address (Example)
	);

	return status;
}