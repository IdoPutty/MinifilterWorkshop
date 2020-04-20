#include "ProcessNotification.h"
#include "FsFilter.h"


namespace ProcessNotification
{

UNICODE_STRING DOS_DEVICE = RTL_CONSTANT_STRING(L"\\DosDevices\\");

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

	// ENTER CODE HERE

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

	// If the join fails - the function won't change the fullPath variable.
	RtlUnicodeStringCatEx(&fullPath, processPath, NULL, STRSAFE_NO_TRUNCATION);

	InitializeObjectAttributes(&objAttr, &fullPath, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);



	// Continue from here!!!!


	// Obtain handle to the file.
	// Read about "Managing Hardware Priorities" in order to dive into: IRQL and "KeGetCurrentIrql()"
	if (KeGetCurrentIrql() != PASSIVE_LEVEL)
		return STATUS_INVALID_DEVICE_STATE;

	ntstatus = ZwCreateFile(&handle,
		GENERIC_WRITE,
		&objAttr, &ioStatusBlock, NULL,
		FILE_ATTRIBUTE_NORMAL,
		0,
		FILE_OVERWRITE_IF,
		FILE_SYNCHRONOUS_IO_NONALERT,
		NULL, 0);

	return false;
}

}



