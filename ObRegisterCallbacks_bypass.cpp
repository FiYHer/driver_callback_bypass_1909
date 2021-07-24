#include <ntifs.h>
#include <ntddk.h>
#include <wdm.h>
#include <intsafe.h>

typedef struct _OBJECT_TYPE_INITIALIZER
{
	/* 0x0000 */ unsigned short Length;
	union
	{
		/* 0x0002 */ unsigned short ObjectTypeFlags;
		struct
		{
			struct /* bitfield */
			{
				/* 0x0002 */ unsigned char CaseInsensitive : 1; /* bit position: 0 */
				/* 0x0002 */ unsigned char UnnamedObjectsOnly : 1; /* bit position: 1 */
				/* 0x0002 */ unsigned char UseDefaultObject : 1; /* bit position: 2 */
				/* 0x0002 */ unsigned char SecurityRequired : 1; /* bit position: 3 */
				/* 0x0002 */ unsigned char MaintainHandleCount : 1; /* bit position: 4 */
				/* 0x0002 */ unsigned char MaintainTypeList : 1; /* bit position: 5 */
				/* 0x0002 */ unsigned char SupportsObjectCallbacks : 1; /* bit position: 6 */
				/* 0x0002 */ unsigned char CacheAligned : 1; /* bit position: 7 */
			}; /* bitfield */
			struct /* bitfield */
			{
				/* 0x0003 */ unsigned char UseExtendedParameters : 1; /* bit position: 0 */
				/* 0x0003 */ unsigned char Reserved : 7; /* bit position: 1 */
			}; /* bitfield */
		}; /* size: 0x0002 */
	}; /* size: 0x0002 */
	/* 0x0004 */ unsigned long ObjectTypeCode;
	/* 0x0008 */ unsigned long InvalidAttributes;
	/* 0x000c */ struct _GENERIC_MAPPING GenericMapping;
	/* 0x001c */ unsigned long ValidAccessMask;
	/* 0x0020 */ unsigned long RetainAccess;
	/* 0x0024 */ enum _POOL_TYPE PoolType;
	/* 0x0028 */ unsigned long DefaultPagedPoolCharge;
	/* 0x002c */ unsigned long DefaultNonPagedPoolCharge;
	/* 0x0030 */ void* DumpProcedure /* function */;
	/* 0x0038 */ void* OpenProcedure /* function */;
	/* 0x0040 */ void* CloseProcedure /* function */;
	/* 0x0048 */ void* DeleteProcedure /* function */;
	union
	{
		/* 0x0050 */ void* ParseProcedure /* function */;
		/* 0x0050 */ void* ParseProcedureEx /* function */;
	}; /* size: 0x0008 */
	/* 0x0058 */ void* SecurityProcedure /* function */;
	/* 0x0060 */ void* QueryNameProcedure /* function */;
	/* 0x0068 */ void* OkayToCloseProcedure /* function */;
	/* 0x0070 */ unsigned long WaitObjectFlagMask;
	/* 0x0074 */ unsigned short WaitObjectFlagOffset;
	/* 0x0076 */ unsigned short WaitObjectPointerOffset;
} OBJECT_TYPE_INITIALIZER, * POBJECT_TYPE_INITIALIZER; /* size: 0x0078 */

typedef struct _EX_PUSH_LOCK_EX
{
	union
	{
		struct /* bitfield */
		{
			/* 0x0000 */ unsigned __int64 Locked : 1; /* bit position: 0 */
			/* 0x0000 */ unsigned __int64 Waiting : 1; /* bit position: 1 */
			/* 0x0000 */ unsigned __int64 Waking : 1; /* bit position: 2 */
			/* 0x0000 */ unsigned __int64 MultipleShared : 1; /* bit position: 3 */
			/* 0x0000 */ unsigned __int64 Shared : 60; /* bit position: 4 */
		}; /* bitfield */
		/* 0x0000 */ unsigned __int64 Value;
		/* 0x0000 */ void* Ptr;
	}; /* size: 0x0008 */
} EX_PUSH_LOCK_EX, * PEX_PUSH_LOCK_EX; /* size: 0x0008 */

typedef struct _OBJECT_TYPE
{
	/* 0x0000 */ struct _LIST_ENTRY TypeList;
	/* 0x0010 */ struct _UNICODE_STRING Name;
	/* 0x0020 */ void* DefaultObject;
	/* 0x0028 */ unsigned char Index;
	/* 0x002c */ unsigned long TotalNumberOfObjects;
	/* 0x0030 */ unsigned long TotalNumberOfHandles;
	/* 0x0034 */ unsigned long HighWaterNumberOfObjects;
	/* 0x0038 */ unsigned long HighWaterNumberOfHandles;
	/* 0x0040 */ struct _OBJECT_TYPE_INITIALIZER TypeInfo;
	/* 0x00b8 */ struct _EX_PUSH_LOCK_EX TypeLock;
	/* 0x00c0 */ unsigned long Key;
	/* 0x00c8 */ struct _LIST_ENTRY CallbackList;
} OBJECT_TYPE, * POBJECT_TYPE; /* size: 0x00d8 */

typedef struct _object_callback_entry_
{
	unsigned short version;
	unsigned short operation_registration_count;
	unsigned long _padding_0;
	void* registration_context;
	UNICODE_STRING altitude;
} object_callback_entry, * pobject_callback_entry;

#pragma pack(1)

typedef struct _object_callback_
{
	LIST_ENTRY list_entry;
	unsigned long long _padding_0;
	pobject_callback_entry handle;
	void* type_address;
	POB_PRE_OPERATION_CALLBACK pre_operation_callback;
	POB_POST_OPERATION_CALLBACK post_operation_callback;
}object_callback, * pobject_callback;

#pragma pack()

// type = 0  进程对象
// type = 1  线程对象
void enum_object_callback(int type)
{
	LIST_ENTRY callback_list;
	if (type == 0)
	{
		if (MmIsAddressValid(PsProcessType) == FALSE) return;
		DbgPrintEx(0, 0, "[%s] PsProcessType address %p \n", __FUNCTION__, PsProcessType);
		callback_list = ((POBJECT_TYPE)(*PsProcessType))->CallbackList;
	}
	else
	{
		if (MmIsAddressValid(PsThreadType) == FALSE) return;
		DbgPrintEx(0, 0, "[%s] PsThreadType address %p \n", __FUNCTION__, PsThreadType);
		callback_list = ((POBJECT_TYPE)(*PsThreadType))->CallbackList;
	}

	pobject_callback objects = (pobject_callback)callback_list.Flink;
	DbgPrintEx(0, 0, "[%s] first object address %p \n", __FUNCTION__, objects);

	do
	{
		if (MmIsAddressValid(objects) == FALSE) break;
		else
		{
			DbgPrintEx(0, 0, "[%s] object address %p, pre callback %p, post callback %p \n", __FUNCTION__,
				objects,
				objects->pre_operation_callback,
				objects->post_operation_callback);

			if (MmIsAddressValid(objects->handle) && MmIsAddressValid(objects->handle->altitude.Buffer))
			{
				DbgPrintEx(0, 0, "[%s] handle address %p, version %d, altitude %ws \n", __FUNCTION__,
					objects->handle,
					objects->handle->version,
					objects->handle->altitude.Buffer);
			}

			objects = (pobject_callback)objects->list_entry.Flink;
		}
	} while (objects != (pobject_callback)callback_list.Flink);
}

EXTERN_C
NTSTATUS
DriverEntry(
	PDRIVER_OBJECT driver,
	PUNICODE_STRING reg)
{
	UNREFERENCED_PARAMETER(driver);
	UNREFERENCED_PARAMETER(reg);

	// Microsoft Windows [版本 10.0.18363.592]
	enum_object_callback(0);
	enum_object_callback(1);

	/*
	绕过办法:
	1. ObUnRegisterCallbacks(handle)
	2. pre callback point = my pre callback
	3. asm ret
	*/

	return STATUS_UNSUCCESSFUL;
}