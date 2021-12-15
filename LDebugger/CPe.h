#pragma once
#include <Windows.h>

class CPe
{
  public:
	// ���� PE
	BOOL ParsePe(const TCHAR* szPath);
	// ��ȡ DOS ͷ
	PIMAGE_DOS_HEADER GetDosHeader();
	PIMAGE_DOS_HEADER GetDosHeader(PBYTE FileBuff);
	// ��ȡ NT ͷ
	PIMAGE_NT_HEADERS GetNtHeader();
	PIMAGE_NT_HEADERS GetNtHeader(PBYTE FileBuff);
	// ��ȡ�ļ�ͷ
	PIMAGE_FILE_HEADER GetFileHeader();
	PIMAGE_FILE_HEADER GetFileHeader(PBYTE FileBuff);
	// ��ȡ��չͷ
	PIMAGE_OPTIONAL_HEADER GetOptionalHeader();
	PIMAGE_OPTIONAL_HEADER GetOptionalHeader(PBYTE FileBuff);
	// ��ȡ����ͷ��
	PIMAGE_SECTION_HEADER GetSectionHeader();
	PIMAGE_SECTION_HEADER GetSectionHeader(PIMAGE_NT_HEADERS pNt);
	// ��ȡ����Ŀ¼��
	PIMAGE_DATA_DIRECTORY GetDirectory();
	// ��ȡ������
	PIMAGE_EXPORT_DIRECTORY GetExportDirectory();
	// ��ȡ�����
	PIMAGE_IMPORT_DESCRIPTOR GetImporTable();
	// ��ȡ�ض�λ��
	PIMAGE_BASE_RELOCATION GetRelocation();
	// ��ȡ��Դ��
	PIMAGE_RESOURCE_DIRECTORY GetResourceTable();
	// �޸��ض�λ
	BOOL FixRelocation(DWORD newBase, DWORD oldBase = 0x400000);
	// ������Դ��
	void ParseResource();
	// ���������
	void ParseImportTable();
	// ����������
	void ParseExportTable();
	// �����ض�λ
	void ParseRelocation();
	// RVA to FOA
	DWORD RvaToFoa(DWORD dwRva);
  private:
	// ����·��
	TCHAR* m_szPath;
	// ���� PE ���ݻ�����
	PBYTE m_FileBuff;
	// �ļ���С
	DWORD m_FileSize;
};


