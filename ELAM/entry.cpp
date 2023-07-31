#define WIN32_LEAN_AND_MEAN		// Exclude rarely-used stuff from Windows headers
#define _NTDRIVER_
#define _KERNEL_MODE
#define DECLSPEC_DEPRECATED_DDK

#define _CRT_SECURE_NO_DEPRECATE
#define _CRT_NON_CONFORMING_SWPRINTFS
#define _NO_CRT_STDIO_INLINE
#define _CRT_SECURE_CPP_OVERLOAD_SECURE_NAMES 0

#if defined(_M_IX86)
#define _X86_
#elif defined(_M_AMD64)
#define _AMD64_
#elif defined(_M_ARM64)
#define _ARM64_
#elif defined(_M_ARM)
#define _ARM_
#endif

#include <sdkddkver.h>
#include <wdm.h>

void NTAPI DriverUnload(PDRIVER_OBJECT /*DriverObject*/)
{
	ExGetPreviousMode();
}

NTSTATUS NTAPI DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING /*RegistryPath*/)
{
	DriverObject->DriverUnload = DriverUnload;

	return STATUS_SUCCESS;
}