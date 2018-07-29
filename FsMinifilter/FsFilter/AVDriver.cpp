#include "AVDriver.h"

UNICODE_STRING THREAT_NAME = RTL_CONSTANT_STRING(L"*VIRUS*");

BOOLEAN IsThreatByFilename(PUNICODE_STRING fileName) {

	/************************************************************************/
	/* STEP 2:																*
	/*			This function should return true if the name of the file 	*
	/*			is virus.exe.												*
	/*																		*
	/************************************************************************/

	// ENTER CODE HERE
	//UNREFERENCED_PARAMETER(fileName);
	BOOLEAN isVirus = FsRtlIsNameInExpression(
		&THREAT_NAME,
		fileName,
		TRUE,
		NULL);

	return isVirus;
}


FLT_PREOP_CALLBACK_STATUS AntiVirusPreReadOperation(
	_Inout_ PFLT_CALLBACK_DATA data,
	_In_ PCFLT_RELATED_OBJECTS fltObjects,
	_Flt_CompletionContext_Outptr_ PVOID* completionContext) {

	UNREFERENCED_PARAMETER(completionContext);

	PUNICODE_STRING fileName = &fltObjects->FileObject->FileName;
	if (IsThreatByFilename(fileName)) {

		/************************************************************************/
		/* STEP 3:																*
		/*		If we found a threat, we need to change the iostatus of the		*
		/*		request and return a value which indicates that we are done		*		
		/*		and the request is complete.									*
		/************************************************************************/
		// ENTER CODE HERE
		data->IoStatus.Status = STATUS_VIRUS_INFECTED;
		data->IoStatus.Information = 0;
		return FLT_PREOP_COMPLETE;

	} else {
		data->IoStatus.Status = STATUS_SUCCESS;
		data->IoStatus.Information = 0;
		return FLT_PREOP_SUCCESS_NO_CALLBACK;
	}
}

