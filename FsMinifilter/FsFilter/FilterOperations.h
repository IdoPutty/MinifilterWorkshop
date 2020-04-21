#pragma once
#include <ntifs.h>
#include <Fltkernel.h>

/*************************************************************************
							Prototypes
*************************************************************************/

BOOLEAN isThreatByFilename(PUNICODE_STRING fileName);

FLT_PREOP_CALLBACK_STATUS preCreateOperation(_Inout_ PFLT_CALLBACK_DATA data,
													_In_ PCFLT_RELATED_OBJECTS fltObjects,
													_Flt_CompletionContext_Outptr_ PVOID *completionContext);