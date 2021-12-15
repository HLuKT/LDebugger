#pragma once
#include <Windows.h>

class CPe
{
  public:
	// 解析 PE
	BOOL ParsePe(const TCHAR* szPath);
	// 获取 DOS 头
	PIMAGE_DOS_HEADER GetDosHeader();
	PIMAGE_DOS_HEADER GetDosHeader(PBYTE FileBuff);
	// 获取 NT 头
	PIMAGE_NT_HEADERS GetNtHeader();
	PIMAGE_NT_HEADERS GetNtHeader(PBYTE FileBuff);
	// 获取文件头
	PIMAGE_FILE_HEADER GetFileHeader();
	PIMAGE_FILE_HEADER GetFileHeader(PBYTE FileBuff);
	// 获取扩展头
	PIMAGE_OPTIONAL_HEADER GetOptionalHeader();
	PIMAGE_OPTIONAL_HEADER GetOptionalHeader(PBYTE FileBuff);
	// 获取区段头表
	PIMAGE_SECTION_HEADER GetSectionHeader();
	PIMAGE_SECTION_HEADER GetSectionHeader(PIMAGE_NT_HEADERS pNt);
	// 获取数据目录表
	PIMAGE_DATA_DIRECTORY GetDirectory();
	// 获取导出表
	PIMAGE_EXPORT_DIRECTORY GetExportDirectory();
	// 获取导入表
	PIMAGE_IMPORT_DESCRIPTOR GetImporTable();
	// 获取重定位表
	PIMAGE_BASE_RELOCATION GetRelocation();
	// 获取资源表
	PIMAGE_RESOURCE_DIRECTORY GetResourceTable();
	// 修复重定位
	BOOL FixRelocation(DWORD newBase, DWORD oldBase = 0x400000);
	// 解析资源表
	void ParseResource();
	// 解析导入表
	void ParseImportTable();
	// 解析导出表
	void ParseExportTable();
	// 解析重定位
	void ParseRelocation();
	// RVA to FOA
	DWORD RvaToFoa(DWORD dwRva);
  private:
	// 保存路径
	TCHAR* m_szPath;
	// 保存 PE 内容缓冲区
	PBYTE m_FileBuff;
	// 文件大小
	DWORD m_FileSize;
};


