#include <ntddk.h>

#include "struct.hpp"

#include "ob.hpp"

NTSTATUS defalut_irp(
	PDEVICE_OBJECT device,
	PIRP irp)
{
	UNREFERENCED_PARAMETER(device);

	irp->IoStatus.Status = STATUS_SUCCESS;
	irp->IoStatus.Information = 0;

	IoCompleteRequest(irp, IO_NO_INCREMENT);
	return STATUS_SUCCESS;
}

NTSTATUS communication_irp(
	PDEVICE_OBJECT device,
	PIRP irp)
{
	UNREFERENCED_PARAMETER(device);

	PIO_STACK_LOCATION io = IoGetCurrentIrpStackLocation(irp);
	ULONG control = io->Parameters.DeviceIoControl.IoControlCode;
	// pcommon_info info = (pcommon_info)irp->AssociatedIrp.SystemBuffer;
	pcommon_info info = (pcommon_info)MmGetSystemAddressForMdlSafe(irp->MdlAddress, NormalPagePriority);

	switch (control)
	{
	case IoGetObCallback:
		_ob::get_ob_callback(info);
		break;
	case IoRemoveObCallback:
		break;
	case IoDisableObCallback:
		break;
	}

	KeFlushIoBuffers(irp->MdlAddress, TRUE, FALSE);
	irp->IoStatus.Status = STATUS_SUCCESS;
	irp->IoStatus.Information = 0;
	IoCompleteRequest(irp, IO_NO_INCREMENT);
	return STATUS_SUCCESS;
}

VOID DriverUnload(PDRIVER_OBJECT driver)
{
	UNREFERENCED_PARAMETER(driver);

	if (g_device_object != nullptr)
	{
		IoDeleteSymbolicLink(&g_symbolic_link);
		IoDeleteDevice(g_device_object);
	}
	g_device_object = nullptr;

	DbgPrintEx(0, 0, "[%s] release \n", __FUNCTION__);
}

EXTERN_C
NTSTATUS
DriverEntry(
	PDRIVER_OBJECT driver,
	PUNICODE_STRING reg)
{
	UNREFERENCED_PARAMETER(driver);
	UNREFERENCED_PARAMETER(reg);

	NTSTATUS status = IoCreateDevice(driver, 0, &g_device_name, FILE_DEVICE_UNKNOWN, FILE_DEVICE_SECURE_OPEN, FALSE, &g_device_object);
	if (!NT_SUCCESS(status))
		return status;

	status = IoCreateSymbolicLink(&g_symbolic_link, &g_device_name);
	if (!NT_SUCCESS(status))
	{
		IoDeleteDevice(g_device_object);
		return status;
	}

	for (int i = 0; i <= IRP_MJ_MAXIMUM_FUNCTION; i++) driver->MajorFunction[i] = defalut_irp;

	driver->MajorFunction[IRP_MJ_DEVICE_CONTROL] = communication_irp;
	driver->DriverUnload = DriverUnload;

	g_device_object->Flags |= DO_DIRECT_IO;
	g_device_object->Flags &= ~DO_DEVICE_INITIALIZING;

	DbgPrintEx(0, 0, "[%s] finish \n", __FUNCTION__);
	return status;
}