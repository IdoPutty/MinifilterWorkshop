#pragma once
#include <Ntddk.h>


typedef struct
{
	UINT32 processIndex;
	PEPROCESS processes[65000];
} ProcessArray;

extern ProcessArray g_processArray;

namespace ProcessNotification 
{
	void registerProcessNotify();
		

	void unregisterProcessNotify();

	void processNotification(
		PEPROCESS Process,
		HANDLE ProcessId,
		PPS_CREATE_NOTIFY_INFO CreateInfo
	);
};


