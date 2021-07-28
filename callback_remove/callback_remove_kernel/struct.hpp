#pragma once

#define IoGetObCallback CTL_CODE(FILE_DEVICE_UNKNOWN, 0x800, METHOD_OUT_DIRECT, FILE_ANY_ACCESS)
#define IoRemoveObCallback CTL_CODE(FILE_DEVICE_UNKNOWN, 0x801, METHOD_OUT_DIRECT, FILE_ANY_ACCESS)
#define IoDisableObCallback CTL_CODE(FILE_DEVICE_UNKNOWN, 0x802, METHOD_OUT_DIRECT, FILE_ANY_ACCESS)

static UNICODE_STRING g_device_name = RTL_CONSTANT_STRING(L"\\Device\\callback_remove");
static UNICODE_STRING g_symbolic_link = RTL_CONSTANT_STRING(L"\\DosDevices\\callback_remove");
static PDEVICE_OBJECT g_device_object = nullptr;

static constexpr unsigned int max_count = 64;

typedef struct _common_info_
{
	unsigned int index;
	unsigned long long address[max_count];
}common_info, * pcommon_info;