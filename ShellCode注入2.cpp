#include<Windows.h>
#include<tchar.h>
#include<iostream>
#define path "C:\\Users\\�޼�\\Desktop\\111.exe"
#define path2 "C:\\Users\\�޼�\\Desktop\\999.exe"

BOOL changePE(DWORD MessageBoxAdd) {
	//���ļ����ڴ���
	HANDLE hFile = CreateFile(path, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	HANDLE hFile2 = CreateFile(path2, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);

	if ((DWORD)hFile == INVALID_FILE_ATTRIBUTES) {
		return -1;
	}
	//��ȡ��С
	DWORD size = GetFileSize(hFile, NULL);
	//����ռ�
	LPVOID buf = new char[size] {0};
	//������
	DWORD readSize = 0;
	ReadFile(hFile, buf, size, &readSize, NULL);

	//����WriteFileд���ļ�
	//�����ļ�ָ���ƫ�ƣ��ο�WriteFile���������һ��������������
	OVERLAPPED overLapped = { 0 };
	overLapped.Offset = 0;
	DWORD writeSize = 0;

	PIMAGE_DOS_HEADER dos_header = PIMAGE_DOS_HEADER(buf);
	PIMAGE_NT_HEADERS nt_header = PIMAGE_NT_HEADERS((DWORD)buf + dos_header->e_lfanew);
	PIMAGE_OPTIONAL_HEADER option_header = PIMAGE_OPTIONAL_HEADER(&(nt_header->OptionalHeader));
	PIMAGE_FILE_HEADER file_header = PIMAGE_FILE_HEADER(&(nt_header->FileHeader));
	PIMAGE_SECTION_HEADER section_header = PIMAGE_SECTION_HEADER(IMAGE_FIRST_SECTION(nt_header));

	//�������Σ��Һ��ʵ�λ�÷Ŵ���
	for (int i = 0; i < file_header->NumberOfSections - 1; i++) {
		//������������ļ��еĴ�С-��������ļ�����ǰʵ�ʴ�С>=18
		if (int(section_header->SizeOfRawData) - int(section_header->Misc.VirtualSize) >= 18) {
			DWORD address = section_header->PointerToRawData + (DWORD)buf;
			address = (DWORD)address + section_header->SizeOfRawData - 18;
			//������Ҫ������ֵ
			//call�ĵ�ַ
			DWORD Offset = address - (DWORD)buf + 8 - section_header->PointerToRawData;
			DWORD CallAddress = MessageBoxAdd - (Offset + section_header->VirtualAddress + option_header->ImageBase) - 5;
			for (int j = 0; j < 2; j++) {
				*(PDWORD)address = 0x006A006A;
				//����ƫ�ƣ�д��
				overLapped.Offset = address - (DWORD)buf;
				WriteFile(hFile, (LPCVOID)address, 4, &writeSize, &overLapped);
				address += 4;
			}
			*(PCHAR)address = 0xE8;
			//����ƫ�ƣ�д��
			overLapped.Offset = address - (DWORD)buf;
			WriteFile(hFile, (LPCVOID)address, 1, &writeSize, &overLapped);
			address++;
			*(PDWORD)address = CallAddress;
			overLapped.Offset = address - (DWORD)buf;
			WriteFile(hFile, (LPCVOID)address, 4, &writeSize, &overLapped);
			address += 4;
			//jmp�ĵ�ַ
			Offset += 5;
			DWORD OEPAddress = option_header->AddressOfEntryPoint;
			//DWORD JmpAddress = OEPAddress + option_header->ImageBase -(Offset + section_header->VirtualAddress + option_header->ImageBase) - 5;
			DWORD JmpAddress = OEPAddress - (Offset + section_header->VirtualAddress) - 5;
			*(PCHAR)address = 0xE9;
			overLapped.Offset = address - (DWORD)buf;
			WriteFile(hFile, (LPCVOID)address, 1, &writeSize, &overLapped);
			address++;
			overLapped.Offset = address - (DWORD)buf;
			*(PDWORD)address = JmpAddress;
			WriteFile(hFile, (LPCVOID)address, 4, &writeSize, &overLapped);

			//oep��Ҫ�޸ĵ�ֵ
			option_header->AddressOfEntryPoint = Offset - 13 + section_header->VirtualAddress;
			overLapped.Offset = (DWORD)option_header + 16 - (DWORD)buf;
			WriteFile(hFile, LPVOID((DWORD)option_header + 16), 4, &writeSize, &overLapped);
			
			DWORD WriteSize = 0;
			WriteFile(hFile2, buf, size,&WriteSize,NULL);
			CloseHandle(hFile);
			CloseHandle(hFile2);
			if (buf != NULL) {
				delete[] buf;
				buf = NULL;
			}
			return 1;
		}
		section_header++;
	}
	if (buf != NULL) {
		delete[] buf;
		buf = NULL;
	}
	return 0;
}

int _tmain(char* argv, char* args[]) {

	HMODULE h = LoadLibrary("user32.dll");
	FARPROC a = GetProcAddress(h, "MessageBoxA");
	HMODULE hModule = GetModuleHandle(NULL);

	changePE((DWORD)a);

	return 0;
}