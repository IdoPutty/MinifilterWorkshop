#include "FsFilter.h"
#include "FilterOperations.h"
#include "ProcessNotification.h"

/// This is the global point to out mini filter instance
PFLT_FILTER g_filterHandle;

#ifdef ALLOC_PRAGMA
#pragma alloc_text(INIT, DriverEntry)
#pragma alloc_text(PAGE, FsFilterUnload)
#endif

///  operation registration
CONST FLT_OPERATION_REGISTRATION FilterCallbacks[] = {

	{ IRP_MJ_CREATE,
	  0,
	  preCreateOperation,
	  NULL },

	{ IRP_MJ_OPERATION_END }
};


///  This defines what we want to filter with FltMgr
CONST FLT_REGISTRATION FilterRegistration = {

	sizeof( FLT_REGISTRATION ),         //  Size
	FLT_REGISTRATION_VERSION,           //  Version
	0,                                  //  Flags
	NULL,                               //  Context
	FilterCallbacks,                    //  Operation callbacks
	FsFilterUnload,                     //  MiniFilterUnload
	NULL,								//  InstanceSetup
	NULL,								//  InstanceQueryTeardown
	NULL,								//  InstanceTeardownStart
	NULL,								//  InstanceTeardownComplete
	NULL,                               //  GenerateFileName
	NULL,                               //  GenerateDestinationFileName
	NULL                                //  NormalizeNameComponent
};



/*************************************************************************
	MiniFilter initialization and unload routines.
*************************************************************************/


NTSTATUS DriverEntry (_In_ PDRIVER_OBJECT DriverObject, _In_ PUNICODE_STRING RegistryPath) {
	
	UNREFERENCED_PARAMETER(RegistryPath);
	__debugbreak();
	NTSTATUS status;

	//  Register with FltMgr to tell it our callback routines
	status = FltRegisterFilter(DriverObject, &FilterRegistration, &g_filterHandle);

	if (NT_SUCCESS(status)) {

		// Start filtering i/o
		status = FltStartFiltering(g_filterHandle);

		/************************************************************************/
		/* STEP 1:																*
		/*		Add a debug print with your name using DbgPrint function.		*
		/*		Compile and test the driver.									*
		/*																		*
		/************************************************************************/
		
		DbgPrint("Putty!");

		if (!NT_SUCCESS( status )) {
			FltUnregisterFilter( g_filterHandle );
		}

		/************************************************************************/
		/* STEP 7:																*
		/*		Register our process notification routine.	 					*
		/*		Do not forget to unregister the process notification during		*
		/*		driver unload.													*
		/*																		*
		/************************************************************************/

		// ENTER CODE HERE

	}

	return status;
}


NTSTATUS FsFilterUnload (_In_ FLT_FILTER_UNLOAD_FLAGS Flags) {
	
	UNREFERENCED_PARAMETER( Flags );

	FltUnregisterFilter( g_filterHandle );

	return STATUS_SUCCESS;
}

