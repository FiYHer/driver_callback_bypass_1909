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

void enum_create_process_notify_routine()
{
	unsigned long long address = 0;
	unsigned long size = 0;
	if (get_module_base_address("ntoskrnl.exe", address, size) == false) return;
	DbgPrintEx(0, 0, "[%s] ntoskrnl address : %p, size : %lld \n", __FUNCTION__, address, size);

	/*
	PAGE:000000014080DF56                 lea     r13, PspCreateProcessNotifyRoutine
	PAGE:000000014080DF5D                 lea     r12, ds:0[r15*8]
	PAGE:000000014080DF65                 add     r12, r13
	PAGE:000000014080DF68                 mov     rcx, r12
	PAGE:000000014080DF6B                 call    ExReferenceCallBackBlock
	PAGE:000000014080DF70                 mov     rdi, rax
	PAGE:000000014080DF73                 test    rax, rax
	PAGE:000000014080DF76                 jz      short loc_14080DFE4

	这里其实是定位PspCreateProcessNotifyRoutine
	*/

	void* PspCreateProcessNotifyRoutine = (void*)find_pattern_image(address,
		"\x4c\x8d\x00\x00\x00\x00\x00\x4e\x8d\x00\x00\x00\x00\x00\x00\x4d\x03\xe5",
		"xx?????xx??????xxx");
	if (PspCreateProcessNotifyRoutine == nullptr) return;
	PspCreateProcessNotifyRoutine = reinterpret_cast<void*>(reinterpret_cast<char*>(PspCreateProcessNotifyRoutine) + 7 + *reinterpret_cast<int*>(reinterpret_cast<char*>(PspCreateProcessNotifyRoutine) + 3));
	DbgPrintEx(0, 0, "[%s] PspCreateProcessNotifyRoutine address %p \n", __FUNCTION__, PspCreateProcessNotifyRoutine);

	// 最多运行64个回调?
	for (unsigned int i = 0; i < 64; i++)
	{
		void* routine_address = *(void**)((unsigned char*)PspCreateProcessNotifyRoutine + sizeof(void*) * i);
		routine_address = (void*)((unsigned long long)routine_address & 0xfffffffffffffff8);
		if (MmIsAddressValid(routine_address))
		{
			routine_address = *(void**)routine_address;
			DbgPrintEx(0, 0, "[%s] [%d] routine address %p\n", __FUNCTION__, i, routine_address);
		}
	}
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
	enum_create_process_notify_routine();

	/*
	PsSetCreateProcessNotifyRoutineEx or PsSetCreateProcessNotifyRoutineEx2 or PsSetCreateProcessNotifyRoutine
	它们的内部都是调用PspSetCreateProcessNotifyRoutine

	移除方法还是那几种没有改变
	*/

	return STATUS_UNSUCCESSFUL;
}
