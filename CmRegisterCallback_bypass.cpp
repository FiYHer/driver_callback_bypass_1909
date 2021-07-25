#include <ntifs.h>
#include <ntddk.h>
#include <ntimage.h>

#ifdef __cplusplus
extern "C"
{
#endif

	typedef struct _SYSTEM_MODULE
	{
		ULONG_PTR Reserved[2];
		PVOID Base;
		ULONG Size;
		ULONG Flags;
		USHORT Index;
		USHORT Unknown;
		USHORT LoadCount;
		USHORT ModuleNameOffset;
		CHAR ImageName[256];
	} SYSTEM_MODULE, * PSYSTEM_MODULE;

	typedef struct _SYSTEM_MODULE_INFORMATION
	{
		ULONG_PTR ulModuleCount;
		SYSTEM_MODULE Modules[1];
	} SYSTEM_MODULE_INFORMATION, * PSYSTEM_MODULE_INFORMATION;

	typedef struct _register_callback_entry_
	{
		LIST_ENTRY list_entry_head;
		unsigned long long _padding_0;
		LARGE_INTEGER cookie;
		void* context;
		void* routine;
	}register_callback_entry, * pregister_callback_entry;

	NTSTATUS
		NTAPI
		ZwQuerySystemInformation(
			DWORD32 systemInformationClass,
			PVOID systemInformation,
			ULONG systemInformationLength,
			PULONG returnLength);

#ifdef __cplusplus
}
#endif

bool get_module_base_address(const char* name, unsigned long long& addr, unsigned long& size)
{
	unsigned long need_size = 0;
	ZwQuerySystemInformation(11, &need_size, 0, &need_size);
	if (need_size == 0) return false;

	const unsigned long tag = 'VMON';
	PSYSTEM_MODULE_INFORMATION sys_mods = (PSYSTEM_MODULE_INFORMATION)ExAllocatePoolWithTag(NonPagedPool, need_size, tag);
	if (sys_mods == 0) return false;

	NTSTATUS status = ZwQuerySystemInformation(11, sys_mods, need_size, 0);
	if (!NT_SUCCESS(status))
	{
		ExFreePoolWithTag(sys_mods, tag);
		return false;
	}

	for (unsigned long long i = 0; i < sys_mods->ulModuleCount; i++)
	{
		PSYSTEM_MODULE mod = &sys_mods->Modules[i];
		if (strstr(mod->ImageName, name))
		{
			addr = (unsigned long long)mod->Base;
			size = (unsigned long)mod->Size;
			break;
		}
	}

	ExFreePoolWithTag(sys_mods, tag);
	return true;
}

bool pattern_check(const char* data, const char* pattern, const char* mask)
{
	size_t len = strlen(mask);

	for (size_t i = 0; i < len; i++)
	{
		if (data[i] == pattern[i] || mask[i] == '?')
			continue;
		else
			return false;
	}

	return true;
}

unsigned long long find_pattern(unsigned long long addr, unsigned long size, const char* pattern, const char* mask)
{
	size -= (unsigned long)strlen(mask);

	for (unsigned long i = 0; i < size; i++)
	{
		if (pattern_check((const char*)addr + i, pattern, mask))
			return addr + i;
	}

	return 0;
}

unsigned long long find_pattern_image(unsigned long long addr, const char* pattern, const char* mask)
{
	PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)addr;
	if (dos->e_magic != IMAGE_DOS_SIGNATURE)
		return 0;

	PIMAGE_NT_HEADERS64 nt = (PIMAGE_NT_HEADERS64)(addr + dos->e_lfanew);
	if (nt->Signature != IMAGE_NT_SIGNATURE)
		return 0;

	PIMAGE_SECTION_HEADER section = IMAGE_FIRST_SECTION(nt);

	for (unsigned short i = 0; i < nt->FileHeader.NumberOfSections; i++)
	{
		PIMAGE_SECTION_HEADER p = &section[i];

		if (strstr((const char*)p->Name, ".text") || 'EGAP' == *reinterpret_cast<int*>(p->Name))
		{
			unsigned long long res = find_pattern(addr + p->VirtualAddress, p->Misc.VirtualSize, pattern, mask);
			if (res) return res;
		}
	}

	return 0;
}

void enum_register_callback()
{
	unsigned long long address = 0;
	unsigned long size = 0;
	if (get_module_base_address("ntoskrnl.exe", address, size) == false) return;
	DbgPrintEx(0, 0, "[%s] ntoskrnl address : %p, size : %lld \n", __FUNCTION__, address, size);

	/*
	PAGE:00000001408271B3                 lea     rcx, CallbackListHead
	PAGE:00000001408271BA                 call    CmListGetNextElement
	PAGE:00000001408271BF                 mov     rdi, rax
	PAGE:00000001408271C2                 mov     [rsp+0B8h+var_78], rax
	PAGE:00000001408271C7                 test    rax, rax
	PAGE:00000001408271CA                 jz      loc_140827297
	PAGE:00000001408271D0                 cmp     [rax+18h], rbx
	PAGE:00000001408271D4                 jnz     short loc_1408271AB
	PAGE:00000001408271D6                 mov     eax, [rax+10h]
	PAGE:00000001408271D9                 mov     [rsp+0B8h+arg_10], eax
	PAGE:00000001408271E0                 test    eax, eax
	PAGE:00000001408271E2                 jz      loc_1408272BF
	PAGE:00000001408271E8                 test    r15d, eax
	PAGE:00000001408271EB                 jnz     short loc_1408271AB
	PAGE:00000001408271ED                 lock or dword ptr [rdi+10h], 80000000h
	PAGE:00000001408271F5                 xor     edx, edx        ; BugCheckParameter1
	PAGE:00000001408271F7                 mov     rcx, r14        ; BugCheckParameter2
	PAGE:00000001408271FA                 call    ExReleasePushLockEx

	这里其实是定位CallbackListHead
	*/

	void* CallbackListHead = (void*)find_pattern_image(address,
		"\x48\x8D\x0D\x00\x00\x00\x00\xE8\x00\x00\x00\x00\x48\x8B\xF8\x48\x89\x44\x24\x00\x48\x85\xC0",
		"xxx????x????xxxxxxx?xxx");
	if (CallbackListHead == nullptr) return;
	CallbackListHead = reinterpret_cast<void*>(reinterpret_cast<char*>(CallbackListHead) + 7 + *reinterpret_cast<int*>(reinterpret_cast<char*>(CallbackListHead) + 3));
	DbgPrintEx(0, 0, "[%s] CallbackListHead address %p \n", __FUNCTION__, CallbackListHead);

	pregister_callback_entry entry = (pregister_callback_entry)CallbackListHead;
	do
	{
		if (MmIsAddressValid(entry) == FALSE || MmIsAddressValid(entry->routine) == FALSE) break;
		else
		{
			DbgPrintEx(0, 0, "[%s] routine %p,cookie %llX\n", __FUNCTION__, entry->routine, entry->cookie.QuadPart);
			entry = (pregister_callback_entry)entry->list_entry_head.Flink;
		}
	} while (CallbackListHead != entry);
}

EXTERN_C
NTSTATUS
DriverEntry(
	PDRIVER_OBJECT driver,
	PUNICODE_STRING reg)
{
	UNREFERENCED_PARAMETER(driver);
	UNREFERENCED_PARAMETER(reg);

	//Microsoft Windows [版本 10.0.18363.592]
	enum_register_callback();

	return STATUS_UNSUCCESSFUL;
}
