/*		MISSED TO DO 		*/

/*
1 - GET THE NAME OF THE FILE THAT'S BEING DELETED IN THE createPreCallback. **DONE**

2 - 
*/

#include <fltKernel.h>
#include <dontuse.h>




// Some Global vars
PFLT_FILTER FilterHandler;

/*		****		THE PROTOTYPES         ****      */

EXTERN_C_START

NTSTATUS ZwQueryInformationProcess(
	IN HANDLE ProcessHandle,
	IN PROCESSINFOCLASS ProcessInformationClass,
	OUT PVOID ProcessInformation,
	IN ULONG ProcessInformationLength,
	OUT PULONG ReturnLength OPTIONAL
);

NTSTATUS FilterUnload(FLT_FILTER_UNLOAD_FLAGS Flags);

NTSTATUS DriverEntry(IN PDRIVER_OBJECT DriverObject, 
	IN PUNICODE_STRING RegistryPath);

FLT_PREOP_CALLBACK_STATUS SetInfoPreCallback(
	_Inout_ PFLT_CALLBACK_DATA Data,
	_In_ PCFLT_RELATED_OBJECTS FltObjects,
	_Flt_CompletionContext_Outptr_ PVOID* CompletionContext);

FLT_PREOP_CALLBACK_STATUS CreatePreCallback(
	_Inout_ PFLT_CALLBACK_DATA Data,
	_In_ PCFLT_RELATED_OBJECTS FltObjects,
	_Flt_CompletionContext_Outptr_ PVOID* CompletionContext);

EXTERN_C_END

// Callback routines :
const FLT_OPERATION_REGISTRATION Callbacks[] =
{
	{IRP_MJ_SET_INFORMATION, 0, SetInfoPreCallback, nullptr}, // Open file with FILE_DELETE_ON_CLOSE
	{IRP_MJ_CREATE, 0, CreatePreCallback, nullptr}, // Delete Operation
	{IRP_MJ_OPERATION_END}
};


// Registration Structure :
const FLT_REGISTRATION FilterRegistration = {
	sizeof(FLT_REGISTRATION),
	FLT_REGISTRATION_VERSION,
	NULL,
	NULL,
	Callbacks,
	FilterUnload,
	NULL,
	NULL,
	NULL,
	NULL,
	NULL,
	NULL,
	NULL,
	NULL,
};


NTSTATUS DriverEntry(IN PDRIVER_OBJECT DriverObject, IN PUNICODE_STRING RegistryPath)
{
	KdPrint(("ENTERING : %s\r\n", __FUNCTION__));

	NTSTATUS status;
	UNREFERENCED_PARAMETER(RegistryPath);

	status = FltRegisterFilter(DriverObject, &FilterRegistration, &FilterHandler);

	if (!NT_SUCCESS(status))
	{
		KdPrint(("miniFilter Driver : FAIL in Registring the filter. error 0x%x\r\n", status));
		return status;
	}


	status = FltStartFiltering(FilterHandler);
	if (!NT_SUCCESS(status))
	{ // Don't forget to undo everything you did before if something failed.
		KdPrint(("Minifilter Driver: FAIL in start filtering. error 0x%x\r\n", status));
		FltUnregisterFilter(FilterHandler);
		return status;
	}

	return STATUS_SUCCESS;
}


NTSTATUS FilterUnload(FLT_FILTER_UNLOAD_FLAGS Flags)
{
	KdPrint(("ENTERING : %s\r\n", __FUNCTION__));

	UNREFERENCED_PARAMETER(Flags);
	FltUnregisterFilter(FilterHandler);
	return STATUS_SUCCESS;
}


FLT_PREOP_CALLBACK_STATUS CreatePreCallback(
	_Inout_ PFLT_CALLBACK_DATA Data,
	_In_ PCFLT_RELATED_OBJECTS FltObjects,
	_Flt_CompletionContext_Outptr_ PVOID* CompletionContext)
{

	KdPrint(("ENTERING : %s\r\n", __FUNCTION__));


	UNREFERENCED_PARAMETER(FltObjects);
	UNREFERENCED_PARAMETER(CompletionContext);

	//KdPrint(("first: trying with the file : %wZ\n", Data->Iopb->TargetFileObject->FileName));

	FLT_PREOP_CALLBACK_STATUS retStatus = FLT_PREOP_SUCCESS_NO_CALLBACK;
	NTSTATUS status;
	auto sizeOfPool = 300;
	PUNICODE_STRING ProcessPath;

	// first check if it came from the kernel :
	if (Data->RequestorMode == KernelMode)
		return retStatus;

	//
	// First, we need to check if the FILE_DELETE_ON_CLOSE flag is passed while openning the file
	//

	auto ParametersForCreate = &Data->Iopb->Parameters.Create;
	
	if (ParametersForCreate->Options & FILE_DELETE_ON_CLOSE) // Now it wants to delete it :
	{
		// now check if the process creator for the request is the cmd
		ProcessPath = (PUNICODE_STRING)ExAllocatePool(PagedPool, sizeOfPool);

		if (ProcessPath == nullptr)
		{
			KdPrint(("mini filter Driver: Can't allocate space to hold the process name.\r\n"));
			return FLT_PREOP_SUCCESS_NO_CALLBACK;
		}
		
		// wipe up every thing.
		RtlZeroMemory(ProcessPath, sizeOfPool);

		// we did "sizeofpool - sizeof(WCHAR)" so to leave a space for the null byte
		status = ZwQueryInformationProcess(NtCurrentProcess(), ProcessImageFileName, ProcessPath, sizeOfPool - sizeof(WCHAR), nullptr);

		if (!NT_SUCCESS(status))
		{
			KdPrint(("Mini Filter Driver: ERROR while query info about the process. error code 0x%x\r\n", status));
			return retStatus;
		}

		//
		// Now we have the process image path, we need to chech it 
		// But Note that the path retrieved is the "Native" path.
		//

		if (wcsstr(ProcessPath->Buffer, L"\\System32\\cmd.exe") != NULL ||
			wcsstr(ProcessPath->Buffer, L"\\SysWOW64\\cmd.exe") != NULL)
		{ // then now the process is the cmd
			KdPrint(("mini filter driver: cmd tries to delete the file %wZ, but apported !!!\r\n", Data->Iopb->TargetFileObject->FileName));

			Data->IoStatus.Status = STATUS_ACCESS_DENIED; // or any error as you want.

			retStatus = FLT_PREOP_COMPLETE; // at this only case.

		}
		
		else
			KdPrint(("catched FILE_DELETE_ON_CLOSE, but not from the cmd. then nothing to do.\r\n"));
	
		ExFreePool(ProcessPath);

	}

	//KdPrint(("no FILE_DELETE_ON_CLOSE was used, done."));
	return retStatus;
}

FLT_PREOP_CALLBACK_STATUS SetInfoPreCallback(
	_Inout_ PFLT_CALLBACK_DATA Data,
	_In_ PCFLT_RELATED_OBJECTS FltObjects,
	_Flt_CompletionContext_Outptr_ PVOID* CompletionContext)
{
	KdPrint(("ENTERING : %s\r\n", __FUNCTION__));
	//UNREFERENCED_PARAMETER(Data);
	UNREFERENCED_PARAMETER(FltObjects);
	UNREFERENCED_PARAMETER(CompletionContext);

	PEPROCESS procAddr;
	NTSTATUS status;
	HANDLE hProcess;
	PUNICODE_STRING ProcessName;
	auto sizeOfPool = 300;
	ULONG retVal;

	FLT_PREOP_CALLBACK_STATUS retStatus = FLT_PREOP_SUCCESS_NO_CALLBACK;

	// check if kernel mode that did this request
	if (Data->RequestorMode == KernelMode)
		return retStatus;

	auto parametersForSetInfo = Data->Iopb->Parameters.SetFileInformation;

	// check if it set the delete strcuture at the first place ...
	if (parametersForSetInfo.FileInformationClass != FileDispositionInformation &&
		parametersForSetInfo.FileInformationClass != FileDispositionInformationEx)
		// now it doesn't want to delete the file :
		return retStatus;

	// now it may contain the FileDispositionInformation class or FileDispositionInformationEx .. 
	if (parametersForSetInfo.FileInformationClass == FileDispositionInformation)
	{
		auto info = static_cast<PFILE_DISPOSITION_INFORMATION>(parametersForSetInfo.InfoBuffer);
		
		// if not set :
		if (!info->DeleteFile)
			return retStatus;
		
		// now it needs to delete the file :
	}

	else
	{
		auto info = static_cast<PFILE_DISPOSITION_INFORMATION_EX>(parametersForSetInfo.InfoBuffer);

		// check if it doesn't want to delete the file ..
		if (!(info->Flags & FILE_DISPOSITION_DELETE))
			return retStatus;

		// now also it needs to delete the file :

	}
	
	procAddr = PsGetThreadProcess(Data->Thread);
	
	status = ObOpenObjectByPointer(procAddr, OBJ_KERNEL_HANDLE, NULL, 0, NULL, KernelMode, &hProcess);

	if (!NT_SUCCESS(status))
	{
		KdPrint(("error, while getting the process handle, with error 0x%x\n", status));
		return retStatus;
	}

	// now we got the handle to the process, it's time to get info about it :

	ProcessName =  static_cast<PUNICODE_STRING>(ExAllocatePool(PagedPool, sizeOfPool));

	if (ProcessName == nullptr)
	{
		KdPrint(("error while allocating the pool.\n"));
		return retStatus;
	}

	status = ZwQueryInformationProcess(hProcess, ProcessImageFileName, ProcessName, sizeOfPool - sizeof(WCHAR), &retVal);

	if (!NT_SUCCESS(status))
	{
		KdPrint(("error, while getting the info about the process, error code : 0x%x", status));
		ExFreePool(ProcessName);
		return retStatus;
	}
	
	if (wcsstr(ProcessName->Buffer, L"\\System32\\cmd.exe") != NULL ||
		wcsstr(ProcessName->Buffer, L"\\SysWOW64\\cmd.exe") != NULL)
	{
		// now its the cmd ..
		retStatus = FLT_PREOP_COMPLETE;

		KdPrint(("CAUTION. caguht cmd trying to delete file but aborted, file name : %wZ\n", Data->Iopb->TargetFileObject->FileName));

		Data->IoStatus.Status = STATUS_ACCESS_DENIED;
		
	}

	ExFreePool(ProcessName);
	return retStatus;

}