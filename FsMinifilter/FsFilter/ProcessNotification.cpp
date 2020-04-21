#include "ProcessNotification.h"
#include "FsFilter.h"


namespace ProcessNotification
{

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
		if (createInfo != NULL)
		{
			PCUNICODE_STRING imageFileName(createInfo->ImageFileName);
			PUNICODE_STRING processPath((PUNICODE_STRING)imageFileName);
			if (isVirus(processPath))
			{
				__debugbreak();
				createInfo->CreationStatus = STATUS_VIRUS_INFECTED;
			}
			
		}
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
		OBJECT_ATTRIBUTES  objAttr;
		//LARGE_INTEGER      byteOffset;
		BOOLEAN rv = FALSE;
		CHAR *bufferMapping = NULL;
		FILE_STANDARD_INFORMATION standardInfo = { 0 };
		IO_STATUS_BLOCK iosb = { 0 };


		InitializeObjectAttributes(&objAttr, processPath, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);

		// Obtain handle to the file."
		if (KeGetCurrentIrql() != PASSIVE_LEVEL) {
			// Checks if the current IRQL is Passive as we need - otherwise - stops the function.
			rv = FALSE;
		}
		else {
			// Probably should change the FILE_OPEN or at least put the call in try{}
			ntstatus = ZwCreateFile(&handle,
				GENERIC_READ,
				&objAttr, &ioStatusBlock,
				NULL,
				FILE_ATTRIBUTE_NORMAL,
				FILE_SHARE_READ,
				FILE_OPEN,
				FILE_SYNCHRONOUS_IO_NONALERT,
				NULL, 0);

			if (NT_SUCCESS(ntstatus)) {
				ntstatus = ZwQueryInformationFile(handle, &iosb, &standardInfo, sizeof(standardInfo), FileStandardInformation);
				if(NT_SUCCESS(ntstatus))
				{ 
					// Something messed up with the ExAllocatePoolWithTag call, and the usage of that memory.
					bufferMapping = (CHAR*)ExAllocatePoolWithTag(NonPagedPool, standardInfo.EndOfFile.LowPart, TAG_BUFFER);
					if (bufferMapping != NULL)
					{
						//byteOffset.LowPart = byteOffset.HighPart = 0;
						ntstatus = ZwReadFile(handle, NULL, NULL, NULL, &ioStatusBlock, bufferMapping, standardInfo.EndOfFile.LowPart, NULL, NULL);
						if (NT_SUCCESS(ntstatus)) {
							bufferMapping[standardInfo.EndOfFile.LowPart - 1] = '\0';
							DbgPrint("%s\n", bufferMapping);
							if (strstr(bufferMapping, THREAT_WORD)) {
								rv = TRUE;
							}
						}
					ExFreePoolWithTag(bufferMapping, TAG_BUFFER);
					ZwClose(handle);
				}
			
				}
			}
		}
		return rv;
	}
}


