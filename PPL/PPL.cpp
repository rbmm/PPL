#include "stdafx.h"

#include "nt.h"

HRESULT GetLastHrEx(ULONG dwError = GetLastError())
{
    NTSTATUS status = RtlGetLastNtStatus();
    return dwError == RtlNtStatusToDosErrorNoTeb(status) ? HRESULT_FROM_NT(status) : HRESULT_FROM_WIN32(dwError);
}

inline ULONG BOOL_TO_ERROR(BOOL f)
{
    return f ? NOERROR : GetLastError();
}

int ShowErrorBox(HWND hWnd, HRESULT dwError, PCWSTR lpCaption, UINT uType)
{
    int r = -1;
    LPCVOID lpSource = 0;
    ULONG dwFlags = FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_IGNORE_INSERTS;

    if ((dwError & FACILITY_NT_BIT) || (0 > dwError && HRESULT_FACILITY(dwError) == FACILITY_NULL))
    {
        dwError &= ~FACILITY_NT_BIT;
    __nt:
        dwFlags = FORMAT_MESSAGE_FROM_HMODULE | FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_IGNORE_INSERTS;

        static HMODULE ghnt;
        if (!ghnt && !(ghnt = GetModuleHandle(L"ntdll"))) return 0;
        lpSource = ghnt;
    }

    PWSTR lpText;
    if (FormatMessageW(dwFlags, lpSource, dwError, 0, (PWSTR)&lpText, 0, 0))
    {
        r = MessageBoxW(hWnd, lpText, lpCaption, uType);
        LocalFree(lpText);
    }
    else if (dwFlags & FORMAT_MESSAGE_FROM_SYSTEM)
    {
        goto __nt;
    }

    return r;
}

HRESULT RegisterElamCert(_In_ LPCWSTR lpFileName)
{
	SYSTEM_ELAM_CERTIFICATE_INFORMATION elam = {
		CreateFileW(lpFileName, FILE_READ_DATA, FILE_SHARE_READ, 0, OPEN_EXISTING, 0, 0)
	};

	if (elam.ElamDriverFile == INVALID_HANDLE_VALUE)
	{
		return GetLastHrEx();
	}

	NTSTATUS status = NtSetSystemInformation(SystemElamCertificateInformation, &elam, sizeof(elam));
	CloseHandle(elam.ElamDriverFile);
	return status ? HRESULT_FROM_NT(status) : status;
}

void CheckPPL()
{
	PWSTR lpCommandLine = GetCommandLineW();

	if (*lpCommandLine == '\n')
	{
		return;
	}

	HRESULT dwError = ERROR_OUTOFMEMORY;

	if (PWSTR lpApplicationName = new WCHAR[MINSHORT])
	{
		if (NOERROR == (dwError = BOOL_TO_ERROR(GetFullPathNameW(L"ELAM.DLL", MINSHORT, lpApplicationName, 0))))
		{
			if (0 <= (dwError = RegisterElamCert(lpApplicationName)))
			{
				GetModuleFileNameW(0, lpApplicationName, MINSHORT);

				if (NOERROR == (dwError = GetLastError()))
				{
					STARTUPINFOEXW si = { { sizeof(si) } };
					SIZE_T AttributeListSize = 0;
					while (ERROR_INSUFFICIENT_BUFFER == (dwError = BOOL_TO_ERROR(InitializeProcThreadAttributeList(
						si.lpAttributeList, 1, 0, &AttributeListSize))) && !si.lpAttributeList)
					{
						si.lpAttributeList = (LPPROC_THREAD_ATTRIBUTE_LIST)alloca(AttributeListSize);
					}

					if (NOERROR == dwError)
					{
						ULONG ProtectionLevel = PROTECTION_LEVEL_ANTIMALWARE_LIGHT;

						if (NOERROR == (dwError = BOOL_TO_ERROR(UpdateProcThreadAttribute(si.lpAttributeList, 0,
							PROC_THREAD_ATTRIBUTE_PROTECTION_LEVEL, &ProtectionLevel, sizeof(ProtectionLevel), 0, 0))))
						{
							PROCESS_INFORMATION pi;

							if (CreateProcessW(lpApplicationName,
								const_cast<PWSTR>(L"\n"),
								NULL,
								NULL,
								FALSE,
								EXTENDED_STARTUPINFO_PRESENT | CREATE_PROTECTED_PROCESS,
								NULL,
								NULL,
								&si.StartupInfo,
								&pi))
							{
								CloseHandle(pi.hThread);
								CloseHandle(pi.hProcess);
							}
							else
							{
								dwError = GetLastError();
							}
						}
					}
				}
			}
		}

		delete[] lpApplicationName;
	}

	if (dwError)
	{
		ShowErrorBox(0, dwError, 0, MB_ICONHAND);
	}

	ExitProcess(dwError);
}

void WINAPI ep(void*)
{
	CheckPPL();

	NTSTATUS status;
	PS_PROTECTION ps;

	if (0 > (status = NtQueryInformationProcess(NtCurrentProcess(), ProcessProtectionInformation, &ps, sizeof(ps), 0)))
	{
		ShowErrorBox(0, HRESULT_FROM_NT(status), 0, MB_ICONHAND);
	}
	else
	{
		WCHAR sztype[16], szsigner[16];
		PCWSTR type = sztype, signer = szsigner;

		switch (ps.Type)
		{
		case PsProtectedTypeNone:
			type = L"     None";
			break;
		case PsProtectedTypeProtectedLight:
			type = L"    Light";
			break;
		case PsProtectedTypeProtected:
			type = L"Protected";
			break;
		default:
			swprintf_s(sztype, _countof(sztype), L"%9u", ps.Type);
		}

		switch (ps.Signer)
		{
		case PsProtectedSignerNone:
			signer = L"None        ";
			break;
		case PsProtectedSignerAuthenticode:
			signer = L"Authenticode";
			break;
		case PsProtectedSignerCodeGen:
			signer = L"CodeGen     ";
			break;
		case PsProtectedSignerAntimalware:
			signer = L"Antimalware ";
			break;
		case PsProtectedSignerLsa:
			signer = L"Lsa         ";
			break;
		case PsProtectedSignerWindows:
			signer = L"Windows     ";
			break;
		case PsProtectedSignerWinTcb:
			signer = L"WinTcb      ";
			break;
		case PsProtectedSignerWinSystem:
			signer = L"WinSystem   ";
			break;
		case PsProtectedSignerApp:
			signer = L"App         ";
			break;
		default:
			swprintf_s(szsigner, _countof(szsigner), L"%12u", ps.Signer);
		}
	
		MessageBoxW(0, signer, type, MB_ICONINFORMATION);
	}

	ExitProcess(0);
}
