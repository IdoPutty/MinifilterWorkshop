#include "ProcessNotification.h"
#include "FsFilter.h"


namespace ProcessNotification
{

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

	// ENTER CODE HERE

	return false;
}

}



