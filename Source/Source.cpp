//
// Author: Jonathan Johnson (@jsecurity101)
//


#include <ntddk.h>

#define DRIVER_TAG 'klbc'
PVOID ProcessRegistrationHandle;
UNICODE_STRING g_RegPath;
NTSTATUS ProcCreateCloseCallback(PDEVICE_OBJECT DeviceObject, PIRP Irp);

_IRQL_requires_max_(DISPATCH_LEVEL)
NTSTATUS CompleteRequest(PIRP Irp, NTSTATUS status = STATUS_SUCCESS, ULONG_PTR info = 0);

void ProcUnloadCallback(PDRIVER_OBJECT DriverObject);

_IRQL_requires_max_(APC_LEVEL)
NTSTATUS RegisterCallbacks(PDRIVER_OBJECT DriverObject, PDEVICE_OBJECT DeviceObject);

_IRQL_requires_max_(APC_LEVEL)
void PostProcessHandleCallback(PVOID RegistrationContext, POB_POST_OPERATION_INFORMATION OperationInformation);

_IRQL_requires_max_(APC_LEVEL)
OB_PREOP_CALLBACK_STATUS PreProcessHandleCallback(PVOID RegistrationContext, POB_PRE_OPERATION_INFORMATION OperationInformation);


extern "C"
NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath) {
	PAGED_CODE();

	g_RegPath.Buffer = (PWSTR)ExAllocatePool2(POOL_FLAG_PAGED,
		RegistryPath->Length, DRIVER_TAG);

	if (g_RegPath.Buffer == NULL) {
		DbgPrint("Failed allocation\n");
		return STATUS_INSUFFICIENT_RESOURCES;
	}

	g_RegPath.Length = g_RegPath.MaximumLength = RegistryPath->Length;
	memcpy(g_RegPath.Buffer, RegistryPath->Buffer, g_RegPath.Length);

	DbgPrint("ProcCallback Driver Entry Called 0x%p\n", DriverObject);
	DbgPrint("Registry Path %wZ\n", g_RegPath);

	DriverObject->DriverUnload = ProcUnloadCallback;
	DriverObject->MajorFunction[IRP_MJ_CREATE] = ProcCreateCloseCallback;
	DriverObject->MajorFunction[IRP_MJ_CLOSE] = ProcCreateCloseCallback;

	UNICODE_STRING name;
	RtlInitUnicodeString(&name, L"\\Device\\ProcCallback");
	PDEVICE_OBJECT DeviceObject;
	NTSTATUS status = IoCreateDevice(DriverObject, 0, &name, FILE_DEVICE_UNKNOWN, 0, FALSE, &DeviceObject);

	if (!NT_SUCCESS(status)) {
		DbgPrint("Error creating device: 0x%X\n", status);
		ExFreePool(g_RegPath.Buffer);
		return status;
	}
	DriverObject->DeviceObject = DeviceObject;
	DeviceObject->Flags |= DO_DIRECT_IO;

	UNICODE_STRING symlink;
	RtlInitUnicodeString(&symlink, L"\\??\\ProcCallback");
	status = IoCreateSymbolicLink(&symlink, &name);
	if (!NT_SUCCESS(status)) {
		DbgPrint("Error creating device: 0x%X\n", status);
		ExFreePool(g_RegPath.Buffer);
		IoDeleteDevice(DeviceObject);
		return status;
	}

	status = RegisterCallbacks(DriverObject, DeviceObject);
	if (!NT_SUCCESS(status)) {
		DbgPrint("Error registering callbacks: 0x%X\n", status);
		ExFreePool(g_RegPath.Buffer);
		return status;
	}

	ExFreePool(g_RegPath.Buffer);
	return status;
}

void ProcUnloadCallback(PDRIVER_OBJECT DriverObject) {
	UNREFERENCED_PARAMETER(DriverObject);
	PAGED_CODE();

	ObUnRegisterCallbacks(ProcessRegistrationHandle);
	DbgPrint((DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "Pre/PostProcessHandleCallback Unloaded\n"));

	UNICODE_STRING symlink;
	RtlInitUnicodeString(&symlink, L"\\??\\ProcCallback");
	IoDeleteSymbolicLink(&symlink);
	IoDeleteDevice(DriverObject->DeviceObject);
	DbgPrint("ProcCallback Driver Unloaded\n");
}


//Function completes the driver requests
_IRQL_requires_max_(DISPATCH_LEVEL)
NTSTATUS CompleteRequest(PIRP Irp, NTSTATUS status, ULONG_PTR info) {
	PAGED_CODE();
	Irp->IoStatus.Status = status;
	Irp->IoStatus.Information = info;
	IoCompleteRequest(Irp, IO_NO_INCREMENT);
	return status;
}

//Function handles the create and close requests. Function just points to CompleteRequest.
NTSTATUS ProcCreateCloseCallback(PDEVICE_OBJECT, PIRP Irp) {
	PAGED_CODE();
	return CompleteRequest(Irp);
}

_IRQL_requires_max_(APC_LEVEL)
NTSTATUS RegisterCallbacks(PDRIVER_OBJECT DriverObject, PDEVICE_OBJECT DeviceObject) {
	UNREFERENCED_PARAMETER(DeviceObject);
	UNREFERENCED_PARAMETER(DriverObject);
	PAGED_CODE();
	NTSTATUS status;

	// Register OB_CALLBACK_REGISTRATION
	// Setting up callback for PsProcessType
	OB_CALLBACK_REGISTRATION CallbackRegistration;
	OB_OPERATION_REGISTRATION OperationRegistration;
	OperationRegistration.ObjectType = PsProcessType;
	OperationRegistration.Operations = OB_OPERATION_HANDLE_CREATE;
	OperationRegistration.PreOperation = PreProcessHandleCallback;
	OperationRegistration.PostOperation = PostProcessHandleCallback;

	// Set members
	UNICODE_STRING Altitude;
	RtlInitUnicodeString(&Altitude, L"385300");
	CallbackRegistration.Version = OB_FLT_REGISTRATION_VERSION;
	CallbackRegistration.OperationRegistrationCount = 1;
	CallbackRegistration.Altitude = Altitude;
	CallbackRegistration.RegistrationContext = NULL;
	CallbackRegistration.OperationRegistration = &OperationRegistration;

	status = ObRegisterCallbacks(&CallbackRegistration, &ProcessRegistrationHandle);
	if (!NT_SUCCESS(status))
	{
		DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "Failed to load ObRegisterCallbacks : 0x%X\n", status);
		return status;
	}
	DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "ObRegisterCallbacks Loaded\n");

	return status;
}

_IRQL_requires_max_(APC_LEVEL)
void PostProcessHandleCallback(PVOID RegistrationContext, POB_POST_OPERATION_INFORMATION OperationInformation) {
	PAGED_CODE();
	UNREFERENCED_PARAMETER(RegistrationContext);
	UNREFERENCED_PARAMETER(OperationInformation);

	ACCESS_MASK AccessRights = OperationInformation->Parameters->CreateHandleInformation.GrantedAccess;

	if (AccessRights != 0x0) {
		if (OperationInformation->Operation == OB_OPERATION_HANDLE_CREATE) {

			PEPROCESS openedProcess = (PEPROCESS)OperationInformation->Object;
			HANDLE targetPID = PsGetProcessId(openedProcess);
			HANDLE sourcePID = PsGetCurrentProcessId();

			if (targetPID == sourcePID) {
				DbgPrint("Process %d created a handle to itself with access rights %d\n", sourcePID, AccessRights);
			}
			else {
				DbgPrint("Process %d created a handle to process %d with access rights %d\n", sourcePID, targetPID, AccessRights);
			}

		}
	}
}

_IRQL_requires_max_(APC_LEVEL)
OB_PREOP_CALLBACK_STATUS PreProcessHandleCallback(PVOID RegistrationContext, POB_PRE_OPERATION_INFORMATION OperationInformation) {
	PAGED_CODE();
	UNREFERENCED_PARAMETER(RegistrationContext);
	UNREFERENCED_PARAMETER(OperationInformation);

	if (OperationInformation->Operation == OB_OPERATION_HANDLE_CREATE) {
		PEPROCESS openedProcess = (PEPROCESS)OperationInformation->Object;
		HANDLE targetPID = PsGetProcessId(openedProcess);
		HANDLE sourcePID = PsGetCurrentProcessId();

		if (targetPID == (HANDLE)2972 && sourcePID == (HANDLE)9084) {
			if (OperationInformation->Parameters->CreateHandleInformation.OriginalDesiredAccess == PROCESS_ALL_ACCESS) {
				OperationInformation->Parameters->CreateHandleInformation.DesiredAccess = 0x1000;
				DbgPrint("Changed rights from PROCESS_ALL_ACCESS to PROCESS_QUERY_LIMITED_ACCESS\n");
			}

		}
	}

	return OB_PREOP_SUCCESS;
}