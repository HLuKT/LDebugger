
#include "CPe.h"
#include <stdio.h>
// 解析 PE 文件，如果是 PE 就返回真
BOOL CPe::ParsePe(const TCHAR* szPath)
{
	// 1.打开文件
	HANDLE hFile = CreateFile(
		szPath,
		GENERIC_READ,
		FILE_SHARE_READ,
		NULL,
		OPEN_EXISTING,
		FILE_ATTRIBUTE_NORMAL,
		NULL);
	if (hFile == INVALID_HANDLE_VALUE || hFile == NULL)
	{
		OutputDebugString(L"打开失败");
		return FALSE;
	}
	// 2.获取文件大小，申请空间
	m_FileSize = GetFileSize(hFile, NULL);
	m_FileBuff = new BYTE[m_FileSize]{};
	// 3.读取文件到缓冲区
	DWORD dwSize;
	DWORD ret =
		ReadFile(hFile, m_FileBuff, m_FileSize, &dwSize, NULL);
	if (ret == FALSE)
	{
		CloseHandle(hFile);
		delete[]m_FileBuff;
		OutputDebugString(L"读取失败\n");
		return FALSE;
	}
	// 4.关闭文件句柄
	CloseHandle(hFile);
	// 5.解析 PE
	PIMAGE_DOS_HEADER pDos = GetDosHeader();
	if (pDos->e_magic != IMAGE_DOS_SIGNATURE)
	{
		OutputDebugString(L"无效 PE 文件\n");
		return FALSE;
	}
	// 获取 NT 头
	PIMAGE_NT_HEADERS pNt = GetNtHeader();
	if (pNt->Signature != IMAGE_NT_SIGNATURE)
	{
		OutputDebugString(L"无效 PE 文件\n");
		return FALSE;
	}
	return TRUE;
}PIMAGE_DOS_HEADER CPe::GetDosHeader()
{
	return GetDosHeader(m_FileBuff);
}
PIMAGE_DOS_HEADER CPe::GetDosHeader(PBYTE FileBuff)
{
	return (PIMAGE_DOS_HEADER)(FileBuff);
}
PIMAGE_NT_HEADERS CPe::GetNtHeader()
{
	return GetNtHeader(m_FileBuff);
}
PIMAGE_NT_HEADERS CPe::GetNtHeader(PBYTE FileBuff)
{
	PIMAGE_NT_HEADERS pNt =
		(PIMAGE_NT_HEADERS)(GetDosHeader()->e_lfanew + (DWORD)FileBuff);
	return pNt;
}
PIMAGE_FILE_HEADER CPe::GetFileHeader()
{
	return GetFileHeader(m_FileBuff);
}
PIMAGE_FILE_HEADER CPe::GetFileHeader(PBYTE FileBuff)
{
	return &GetNtHeader()->FileHeader;
}
PIMAGE_OPTIONAL_HEADER CPe::GetOptionalHeader()
{
	return GetOptionalHeader(m_FileBuff);
}
PIMAGE_OPTIONAL_HEADER CPe::GetOptionalHeader(PBYTE FileBuff)
{
	return &GetNtHeader()->OptionalHeader;
}
PIMAGE_SECTION_HEADER CPe::GetSectionHeader()
{
	auto pNt = GetNtHeader();
	return GetSectionHeader(pNt);
}
PIMAGE_SECTION_HEADER CPe::GetSectionHeader(PIMAGE_NT_HEADERS pNt)
{
	return IMAGE_FIRST_SECTION(pNt);
}
PIMAGE_DATA_DIRECTORY CPe::GetDirectory()
{
	// 获取数据目录表
	return GetOptionalHeader()->DataDirectory;
}
PIMAGE_EXPORT_DIRECTORY CPe::GetExportDirectory()
{
	PIMAGE_DATA_DIRECTORY pDir = GetDirectory();
	// 导出表的 RVA
	DWORD Rva = pDir[0].VirtualAddress;
	// 将 RVA 转换 FOA
	DWORD Exportoffset = RvaToFoa(Rva);
	// 转换成导出表结构体
	return (PIMAGE_EXPORT_DIRECTORY)(Exportoffset + m_FileBuff);
}
PIMAGE_IMPORT_DESCRIPTOR CPe::GetImporTable()
{
	auto pImportTable =
		(PIMAGE_IMPORT_DESCRIPTOR)(RvaToFoa(GetDirectory()[1].VirtualAddress) +
			(DWORD)m_FileBuff);
	return pImportTable;
}
PIMAGE_BASE_RELOCATION CPe::GetRelocation()
{
	return (PIMAGE_BASE_RELOCATION)(RvaToFoa(GetDirectory()[5].VirtualAddress) +
		(DWORD)m_FileBuff);

}
PIMAGE_RESOURCE_DIRECTORY CPe::GetResourceTable()
{
	return (PIMAGE_RESOURCE_DIRECTORY)(RvaToFoa(GetDirectory()[2].VirtualAddress) +
		(DWORD)m_FileBuff);
}
typedef struct _TYPEDATA {
	WORD offset : 12;
	WORD type : 4;
}TYPEDATA, * PTYPEDATA;
BOOL CPe::FixRelocation(DWORD newBase, DWORD oldBase)
{
	auto pRelTable = GetRelocation();
	while (pRelTable->SizeOfBlock)
	{
		DWORD dwCount = (pRelTable->SizeOfBlock - 8) / 2;
		// 获取数据项的首地址
		PTYPEDATA pData = (PTYPEDATA)(pRelTable + 1);
		// 遍历该页所有数据项
		for (int i = 0; i < dwCount; i++)
		{
			if (pData[i].type == 3)
			{
				// 获取待修复的数据 0x402000 -》 hello world
				DWORD* pRelocalData =
					(DWORD*)(RvaToFoa(pRelTable->VirtualAddress + pData[i].offset) +
						m_FileBuff);
				// 0x402000 - 0x400000 + 0x800000
				*pRelocalData = *pRelocalData - oldBase + newBase;
			}
		}
		// 找到下一个重定位的结构体
		pRelTable = (PIMAGE_BASE_RELOCATION)((DWORD)pRelTable +
			pRelTable->SizeOfBlock);
	}
	// 保存到文件中
	HANDLE hfile = CreateFile(L"testn.exe",
		GENERIC_WRITE,
		FILE_SHARE_READ,
		NULL,
		CREATE_NEW,
		FILE_ATTRIBUTE_NORMAL,
		NULL);

	DWORD dwSzie = 0;
	WriteFile(hfile, m_FileBuff, m_FileSize, &dwSzie, NULL);
	CloseHandle(hfile);
	return 0;
}
void CPe::ParseResource()
{
	auto pResTable = GetResourceTable();
	//第一层资源种类个数
	DWORD dwCount = pResTable->NumberOfIdEntries +
		pResTable->NumberOfNamedEntries;
	// 资源入口
	PIMAGE_RESOURCE_DIRECTORY_ENTRY pOneResEntry =
		(PIMAGE_RESOURCE_DIRECTORY_ENTRY)(pResTable + 1);
	for (int i = 0; i < dwCount; i++)
	{
		if (pOneResEntry[i].NameIsString) //字符串作为 ID
		{
			PIMAGE_RESOURCE_DIRECTORY_STRING pString =
				(PIMAGE_RESOURCE_DIRECTORY_STRING)(pOneResEntry->NameOffset
					+ (DWORD)pResTable);
			printf("%s\n", pString->NameString);
		}
		else {
			printf("%d\n", pOneResEntry->Id);
		}
		// 第二层资源，表示这中资源个数（png）
		PIMAGE_RESOURCE_DIRECTORY pTwoResTable =
			(PIMAGE_RESOURCE_DIRECTORY)(pOneResEntry->OffsetToDirectory +
				(DWORD)pResTable);
		// 获取这个资源有多少个
		DWORD dwCount2 = pTwoResTable->NumberOfIdEntries +
			pTwoResTable->NumberOfNamedEntries;

		// 资源入口
		PIMAGE_RESOURCE_DIRECTORY_ENTRY pTwoResEntry =
			(PIMAGE_RESOURCE_DIRECTORY_ENTRY)(pTwoResTable + 1);
		for (int j = 0; j < dwCount2; j++)
		{
			if (pTwoResEntry[i].NameIsString)
			{
				PIMAGE_RESOURCE_DIRECTORY_STRING pString =

					(PIMAGE_RESOURCE_DIRECTORY_STRING)(pTwoResEntry->NameOffset +
						(DWORD)pResTable);
				printf("%s\n", pString->NameString);
			}
			else {
				printf("%d\n", pTwoResEntry->Id);
			}
			// 第三层，资源数具体信息
			PIMAGE_RESOURCE_DIRECTORY pThreeResTable =
				(PIMAGE_RESOURCE_DIRECTORY)(pTwoResEntry->OffsetToDirectory +
					(DWORD)pResTable);
			PIMAGE_RESOURCE_DIRECTORY_ENTRY pThreeResEntry =
				(PIMAGE_RESOURCE_DIRECTORY_ENTRY)(pThreeResTable + 1);
			// 第三层指向数据
			PIMAGE_RESOURCE_DATA_ENTRY pDataEntry =
				(PIMAGE_RESOURCE_DATA_ENTRY)(pThreeResEntry->OffsetToData +
					(DWORD)pResTable);
			printf("RVA : %08x Size:%08x\n", pDataEntry->OffsetToData,
				pDataEntry->Size);

		}
	}
}
void CPe::ParseImportTable()
{
	// 获取导入表
	PIMAGE_IMPORT_DESCRIPTOR pImportTable = GetImporTable();
	// 导入表可能有多个
	while (pImportTable->Name)
	{
		// 导入 dll 名称
		char* DllName = (char*)(RvaToFoa(pImportTable->Name) + m_FileBuff);
		printf("DllName: %s \n", DllName);
		// 解析 INT 或者 IAT
		auto pIAT =
			(PIMAGE_THUNK_DATA)(RvaToFoa(pImportTable->FirstThunk) + m_FileBuff);
		// IAT 有多个导入函数，需要遍历
		while (pIAT->u1.Function)
		{
			// 判断是名称导入，还是序号导入
			if (pIAT->u1.Ordinal & 0x80000000) //序号导入
			{
				printf("\t\t order:%02x \n", pIAT->u1.AddressOfData & 0xFFFF);
			}
			else { // 名称导入
				PIMAGE_IMPORT_BY_NAME pByName =
					(PIMAGE_IMPORT_BY_NAME)(RvaToFoa(pIAT->u1.Function) +
						m_FileBuff);
				printf("\t\t order:%02x \t Fun: %s \n", pByName->Hint, pByName->Name);
			}
			pIAT++;
		}
		// 下一个导入表
		pImportTable++;
	}
}
void CPe::ParseExportTable()
{
	PIMAGE_EXPORT_DIRECTORY pExport = GetExportDirectory();
	// 函数基数
	DWORD dwBase = pExport->Base;
	// 导出的 dll 名称
	char* dllName = (char*)(RvaToFoa(pExport->Name) + m_FileBuff);
	printf("Name:%s\n", dllName);
	// 函地址表
	DWORD* pEAT =
		(DWORD*)(RvaToFoa(pExport->AddressOfFunctions) + m_FileBuff);
	// 名称表
	DWORD* pENT =
		(DWORD*)(RvaToFoa(pExport->AddressOfNames) + m_FileBuff);
	// 序号表
	WORD* pEOT =
		(WORD*)(RvaToFoa(pExport->AddressOfNameOrdinals) + m_FileBuff);
	// 解析导出所有函数地址个数
	for (int i = 0; i < pExport->NumberOfFunctions; i++)
	{
		printf("[%d]:0x%08x \t", i + dwBase, pEAT[0]);
		// 看一下这个函数是否有名称
		for (int j = 0; j < pExport->NumberOfNames; j++)
		{
			if (pEOT[j] == i) // 序号表中的值与函数地址下标相同，这个函数有名字
			{
				// 获取函数名称
				char* FunName = (char*)(RvaToFoa(pENT[j]) + m_FileBuff);
				printf("%s \n", FunName);
			}
		}
	}
}
void CPe::ParseRelocation()
{
	auto pRelTable = GetRelocation();
	while (pRelTable->SizeOfBlock)
	{
		printf("VirtualAddress:0x%08x\n", pRelTable->VirtualAddress);
		DWORD dwCount = (pRelTable->SizeOfBlock - 8) / 2;
		// 获取数据项的首地址
		PTYPEDATA pData = (PTYPEDATA)(pRelTable + 1);
		// 遍历该页所有数据项
		for (int i = 0; i < dwCount; i++)
		{
			// 获取待修复的数据
			DWORD* pRelocalData =
				(DWORD*)(RvaToFoa(pRelTable->VirtualAddress + pData[i].offset) +
					m_FileBuff);
			printf("\t type :%02X \t offset :0X%08X Rva: 0X%08x DATA 0X%08X\n",
				pData[i].type,
				pData[i].offset,
				pRelTable->VirtualAddress + pData[i].offset,
				*pRelocalData
			);

		}
		// 找到下一个重定位的结构体
		pRelTable = (PIMAGE_BASE_RELOCATION)((DWORD)pRelTable +
			pRelTable->SizeOfBlock);
	}
}
DWORD CPe::RvaToFoa(DWORD dwRva)
{
	// 区段头部
	PIMAGE_SECTION_HEADER pSection = GetSectionHeader();
	// 区段个数
	DWORD SectionSize = GetFileHeader()->NumberOfSections;
	// 判断 Rva 落在哪个区段上
	for (int i = 0; i < SectionSize; i++) {
		if (dwRva >= pSection[i].VirtualAddress &&
			dwRva < pSection[i].VirtualAddress + pSection[i].SizeOfRawData)
		{
			// Foa = dwRva - 区段内存偏移 + 区段在文件中的偏移
			return dwRva - pSection[i].VirtualAddress + pSection[i].PointerToRawData;
		}
	}
	return -1;
}
