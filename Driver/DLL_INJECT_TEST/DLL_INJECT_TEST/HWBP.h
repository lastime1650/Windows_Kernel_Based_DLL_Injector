#ifndef HWBP_H
#define HWBP_H

#include <ntifs.h>


NTSTATUS Set_Hardware_BreakPoint(
	HANDLE ProcessId,
	PUCHAR TargetAddress
);

//NTSTATUS Unset_Hardware_BreakPoint(HANDLE ProcessId);

#endif