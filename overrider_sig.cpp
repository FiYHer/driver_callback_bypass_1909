#include <windows.h>

#include <iostream>
#include <string>
#include <memory>

typedef struct _security_information_
{
	unsigned char* sig_data;
	unsigned long sig_size;
	unsigned long sig_offset;
}security_information, * psecurity_information;

bool read_sig_data(std::string exe, security_information& out)
{
	HANDLE h = CreateFileA(exe.c_str(), GENERIC_READ, FILE_SHARE_READ, 0, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, 0);
	if (h == INVALID_HANDLE_VALUE) return false;

	unsigned long size = GetFileSize(h, 0);
	std::shared_ptr<unsigned char> buffer(new unsigned char[size]);

	DWORD res = 0;
	BOOL b = ReadFile(h, buffer.get(), size, &res, 0);
	CloseHandle(h);
	if (b == FALSE || res != size) return false;

	PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)buffer.get();
	if (dos->e_magic != IMAGE_DOS_SIGNATURE) return false;

	PIMAGE_NT_HEADERS64 nt = (PIMAGE_NT_HEADERS64)(buffer.get() + dos->e_lfanew);
	if (nt->Signature != IMAGE_NT_SIGNATURE) return false;

	DWORD sig_rva = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_SECURITY].VirtualAddress;
	DWORD sig_size = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_SECURITY].Size;
	if (sig_rva == 0 || sig_size == 0) return false;

	out.sig_data = new unsigned char[sig_size];
	if (out.sig_data == NULL) return false;

	out.sig_size = sig_size;
	out.sig_offset = sig_rva;
	memcpy(out.sig_data, buffer.get() + sig_rva, sig_size);

	return true;
}

bool write_sig_data(std::string exe, const unsigned char* sig_data, unsigned long sig_size, unsigned long sig_offset)
{
	HANDLE h = CreateFileA(exe.c_str(), GENERIC_WRITE, FILE_SHARE_WRITE, 0, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, 0);
	if (h == INVALID_HANDLE_VALUE) return false;

	SetFilePointer(h, sig_offset, NULL, FILE_BEGIN);

	DWORD ret = 0;
	BOOL b = WriteFile(h, sig_data, sig_size, &ret, 0);
	CloseHandle(h);

	return b && ret == sig_size;
}

void overrider_sig(std::string app1, std::string app2)
{
	security_information info1{ 0 };
	bool b = read_sig_data(app1, info1);
	if (b == false)
	{
		std::cout << "[-] read first sig information error" << std::endl;
		return;
	}

	security_information info2{ 0 };
	b = read_sig_data(app2, info2);
	if (b == false)
	{
		std::cout << "[-] read second sig information error" << std::endl;
		return;
	}

	std::printf("[+] first sig size is %d \n", info1.sig_size);
	std::printf("[+] second sig size is %d \n", info2.sig_size);

	// 确保大小
	unsigned long sig_size = info1.sig_size > info2.sig_size ? info2.sig_size : info1.sig_size;

	// 将1的签名数据写入2
	b = write_sig_data(app2, info1.sig_data, sig_size, info2.sig_offset);

	if (b) std::cout << "[+] overrider success" << std::endl;
	else std::cout << "[-] overrider error" << std::endl;
}

int main(int argc, char* argv[])
{
	if (argc != 3)
	{
		std::cout << "[?] overrider_sig.exe src.exe sig.exe" << std::endl;
		return 0;
	}

	overrider_sig(argv[1], argv[2]);
	return 0;
}
