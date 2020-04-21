#include "ProcessNotification.h"
#include "FsFilter.h"


namespace ProcessNotification
{

	UNICODE_STRING DOS_DEVICE = RTL_CONSTANT_STRING(L"\\DosDevices\\");
	const char THREAT_WORD[] = "virus";

	bool registerProcessNotify() {

		/************************************************************************/
		/* STEP 4:																*
		/*		Use PsSetCreateProcessNotifyRoutineEx in order to register		*
		/*		processNotification function on every process creation.			*
		/*		Do not forget to implement the unregister function.				*
		/*																		*
		/************************************************************************/

		NTSTATUS status = PsSetCreateProcessNotifyRoutineEx(processNotification, FALSE);

		return status;
	}

	void unregisterProcessNotify() {

		PsSetCreateProcessNotifyRoutineEx(processNotification, TRUE);
	}

	void processNotification(PEPROCESS process,
		HANDLE processId,
		PPS_CREATE_NOTIFY_INFO createInfo) {

		UNREFERENCED_PARAMETER(processId);
		UNREFERENCED_PARAMETER(process);
		UNREFERENCED_PARAMETER(createInfo);

		/************************************************************************/
		/* STEP 6:																*
		/*		In case of process creation check whether the file content		*
		/*		contains the word 'virus'.										*
		/*		If so block the process from running.							*
		/*		In order to get process name use: createInfo->ImageFileName		*
		/*																		*
		/************************************************************************/

		//// ENTER CODE HERE
		//if (isVirus(createInfo->ImageFileName))
		//{
		//	
		//}
		PUNICODE_STRING processPath((PUNICODE_STRING)createInfo->ImageFileName);
		isVirus(processPath);
	}

	bool isVirus(PUNICODE_STRING processPath) {

		UNREFERENCED_PARAMETER(processPath);


		/************************************************************************/
		/* STEP 5:																*
		/*		Read the file with the given path and check whether it			*
		/*		contains the word 'virus'. Do so by using the following API:	*
		/*		ZwCreateFile, ZwQueryInformationFile, ZwReadFile, ZwClose		*
		/*																		*
		/************************************************************************/


		HANDLE   handle;
		NTSTATUS ntstatus;
		IO_STATUS_BLOCK    ioStatusBlock;
		UNICODE_STRING fullPath = DOS_DEVICE;
		OBJECT_ATTRIBUTES  objAttr;
		LARGE_INTEGER      byteOffset;
		CHAR buffer[BUFFER_SIZE];
		BOOLEAN rv = FALSE;

		// If the join fails - the function won't change the fullPath variable.
		RtlUnicodeStringCatEx(&fullPath, processPath, NULL, STRSAFE_NO_TRUNCATION);

		InitializeObjectAttributes(&objAttr, &fullPath, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);

		// Obtain handle to the file."
		if (KeGetCurrentIrql() != PASSIVE_LEVEL) {
			// Checks if the current IRQL is Passive as we need - otherwise - stops the function.
			rv = FALSE;
		}
		else {
			ntstatus = ZwCreateFile(&handle,
				GENERIC_WRITE,
				&objAttr, &ioStatusBlock, NULL,
				FILE_ATTRIBUTE_NORMAL,
				0,
				FILE_OVERWRITE_IF,
				FILE_SYNCHRONOUS_IO_NONALERT,
				NULL, 0);


			if (NT_SUCCESS(ntstatus)) {
				byteOffset.LowPart = byteOffset.HighPart = 0;
				ntstatus = ZwReadFile(handle, NULL, NULL, NULL, &ioStatusBlock, buffer, BUFFER_SIZE, &byteOffset, NULL);
				if (NT_SUCCESS(ntstatus)) {
					buffer[BUFFER_SIZE - 1] = '\0';
					DbgPrint("%s\n", buffer);

					if (strstr(buffer, THREAT_WORD)) {
						rv = TRUE;
					}
				}
			}
			ZwClose(handle);
		}
		return rv;
	}
}


