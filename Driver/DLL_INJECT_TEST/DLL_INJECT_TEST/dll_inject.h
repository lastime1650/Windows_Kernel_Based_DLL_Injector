#ifndef DLL_INJECT_H
#define DLL_INJECT_H

#include "structs.h"

NTSTATUS DLL_Inject(

    _In_ HANDLE ProcessId, // Target Process ID

    _In_ PCHAR Injection_Dll_PATH // Hacking Dll Path
);

#endif 