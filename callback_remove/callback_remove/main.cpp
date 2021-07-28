#include <windows.h>
#include <winternl.h>
#include <tchar.h>
#pragma comment(lib,"ntdll.lib")

#include "loader.hpp"

#include <iostream>
#include <string>
#include <vector>
#include <codecvt>

// driver start

#define IoGetObCallback CTL_CODE(FILE_DEVICE_UNKNOWN, 0x800, METHOD_OUT_DIRECT, FILE_ANY_ACCESS)
#define IoRemoveObCallback CTL_CODE(FILE_DEVICE_UNKNOWN, 0x801, METHOD_OUT_DIRECT, FILE_ANY_ACCESS)
#define IoDisableObCallback CTL_CODE(FILE_DEVICE_UNKNOWN, 0x802, METHOD_OUT_DIRECT, FILE_ANY_ACCESS)

static constexpr unsigned int max_count = 64;

typedef struct _common_info_
{
	unsigned int index;
	unsigned long long address[max_count];
}common_info, * pcommon_info;

// driver end

typedef struct _RTL_PROCESS_MODULE_INFORMATION
{
	HANDLE Section;
	PVOID MappedBase;
	PVOID ImageBase;
	ULONG ImageSize;
	ULONG Flags;
	USHORT LoadOrderIndex;
	USHORT InitOrderIndex;
	USHORT LoadCount;
	USHORT OffsetToFileName;
	UCHAR  FullPathName[256];
} RTL_PROCESS_MODULE_INFORMATION, * PRTL_PROCESS_MODULE_INFORMATION;

typedef struct _RTL_PROCESS_MODULES
{
	ULONG NumberOfModules;
	RTL_PROCESS_MODULE_INFORMATION Modules[1];
} RTL_PROCESS_MODULES, * PRTL_PROCESS_MODULES;

extern "C" NTSTATUS __stdcall NtQuerySystemInformation(IN SYSTEM_INFORMATION_CLASS SystemInformationClass, OUT PVOID SystemInformation, IN ULONG SystemInformationLength, OUT PULONG ReturnLength OPTIONAL);

std::wstring to_wstring(std::string str)
{
	using convert_typeX = std::codecvt_utf8<wchar_t>;
	std::wstring_convert<convert_typeX, wchar_t> converterX;
	return converterX.from_bytes(str);
}

std::string to_string(std::wstring str)
{
	using convert_typeX = std::codecvt_utf8<wchar_t>;
	std::wstring_convert<convert_typeX, wchar_t> converterX;
	return converterX.to_bytes(str);
}

std::string get_system_module_name(unsigned long long address)
{
	std::string result = "unknown.sys";

	unsigned long size = 0;
	NTSTATUS status = NtQuerySystemInformation((SYSTEM_INFORMATION_CLASS)11, nullptr, size, &size);
	if (size == 0) return result;

	unsigned char* ptr = new unsigned char[size + 1];
	if (ptr == nullptr) return result;

	status = NtQuerySystemInformation((SYSTEM_INFORMATION_CLASS)11, ptr, size, &size);
	if (!NT_SUCCESS(status))
	{
		delete[] ptr;
		return result;
	}

	PRTL_PROCESS_MODULES modules = (PRTL_PROCESS_MODULES)ptr;
	for (unsigned long i = 0; i < modules->NumberOfModules; i++)
	{
		RTL_PROCESS_MODULE_INFORMATION& mod = modules->Modules[i];
		if (address > (unsigned long long)mod.ImageBase && address < (unsigned long long)mod.ImageBase + mod.ImageSize)
		{
			result = (const char*)mod.FullPathName;
			result = result.substr(result.rfind("\\") + 1);
			break;
		}
	}

	delete[] ptr;
	return result;
}

int open_driver(HANDLE& h)
{
	h = CreateFileA("\\\\.\\callback_remove", 0, FILE_SHARE_READ | FILE_SHARE_WRITE, 0, OPEN_EXISTING, 0, 0);
	if (h != INVALID_HANDLE_VALUE) return 1;

	auto get_driver_path = []() -> std::wstring
	{
		wchar_t path[0x100]{ 0 };
		GetModuleFileNameW(NULL, path, 0x100);
		wcsrchr(path, L'\\')[1] = 0;
		wcscat_s(path, L"callback_remove_kernel.sys");
		return std::wstring{ path };
	};

	bool b = start_install_driver(get_driver_path().c_str(), L"callback_control_service", true);
	if (b)
	{
		h = CreateFileA("\\\\.\\callback_remove", 0, FILE_SHARE_READ | FILE_SHARE_WRITE, 0, OPEN_EXISTING, 0, 0);
		if (h != INVALID_HANDLE_VALUE) return 2;
	}

	return 0;
}

void close_driver(int result, HANDLE h)
{
	if (h != INVALID_HANDLE_VALUE) CloseHandle(h);
	if (result == 2) start_uninstall_driver(L"callback_control_service");
}

std::vector<unsigned long long> get_ob_callback(HANDLE h)
{
	std::vector<unsigned long long> result;

	if (h == INVALID_HANDLE_VALUE) return result;

	common_info info{ 0 };

	DWORD r = 0;
	BOOL ret = DeviceIoControl(h, IoGetObCallback, &info, sizeof(info), &info, sizeof(info), &r, 0);
	for (unsigned int i = 0; i < info.index; i++) result.push_back(info.address[i]);

	return result;
}

void menu()
{
	printf("  _   _      _ _    __        __         _     _ \n"
		" | | | | ___| | | __\\ \\      / /__  _ __| | __| |\n"
		" | |_| |/ _ \\ | |/ _ \\ \\ /\\ / / _ \\| '__| |/ _` |\n"
		" |  _  |  __/ | | (_) \\ V  V / (_) | |  | | (_| |\n"
		" |_| |_|\\___|_|_|\\___/ \\_/\\_/ \\___/|_|  |_|\\__,_|\n\n\n");

	printf("[?] 介绍:这是一个移除内核各种回调函数的工具 \n");
	printf("[?] 目的:移除反作弊系统的回调 \n");
	printf("[?] 作用:反句柄权限剥离,反进程扫描,反线程扫描,反动态链接库扫描 \n\n");

	printf("[?] -show \t 显示全部回调信息 \n");
	printf("[?] -index \t 指定回调索引 \n");
	printf("[?] -remove \t 直接移除回调 \n");
	printf("[?] -disable \t 让回调无效 \n");
	printf("[?] -cm \t CmRegisterCallback类驱动 \n");
	printf("[?] -ob \t ObRegisterCallback类驱动 \n");
	printf("[?] -process \t PsSetCreateProcessNotifyRoutine类驱动 \n");
	printf("[?] -thread \t PsSetCreateThreadNotifyRoutine类驱动 \n");
	printf("[?] -image \t PsSetLoadImageNotifyRoutine类驱动 \n\n");

	printf("[?] 例子:\n");
	printf("[?] callback_remove.exe -show -cm\n");
	printf("[?] callback_remove.exe -remove -cm -index 0,1,2,3 \n");

	getchar();
}

void parser(int argc, char* argv[])
{
	auto is_exist_parameter = [&](std::string para) -> bool
	{
		for (int i = 1; i < argc; i++)
			if (std::string{ argv[i] } == para)
				return true;
		return false;
	};

	if (is_exist_parameter("-show"))
	{
		HANDLE h = INVALID_HANDLE_VALUE;
		int result = open_driver(h);
		if (result == 0)
		{
			printf("[-] 加载驱动程序失败 \n");
			return;
		}

		if (is_exist_parameter("-ob"))
		{
			std::vector<unsigned long long> calls = get_ob_callback(h);
			for (size_t i = 0; i < calls.size(); i++)
			{
				unsigned long long address = calls[i];
				printf("[+] [object callback] [%lld] - [%llx] - [%s] \n", i, address, get_system_module_name(address).c_str());
			}
		}

		close_driver(result, h);
	}
}

int main(int argc, char* argv[])
{
	if (argc < 3) menu();
	else parser(argc, argv);

	return 0;
}