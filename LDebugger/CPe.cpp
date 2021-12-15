
#include "CPe.h"
#include <stdio.h>
// ���� PE �ļ�������� PE �ͷ�����
BOOL CPe::ParsePe(const TCHAR* szPath)
{
	// 1.���ļ�
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
		OutputDebugString(L"��ʧ��");
		return FALSE;
	}
	// 2.��ȡ�ļ���С������ռ�
	m_FileSize = GetFileSize(hFile, NULL);
	m_FileBuff = new BYTE[m_FileSize]{};
	// 3.��ȡ�ļ���������
	DWORD dwSize;
	DWORD ret =
		ReadFile(hFile, m_FileBuff, m_FileSize, &dwSize, NULL);
	if (ret == FALSE)
	{
		CloseHandle(hFile);
		delete[]m_FileBuff;
		OutputDebugString(L"��ȡʧ��\n");
		return FALSE;
	}
	// 4.�ر��ļ����
	CloseHandle(hFile);
	// 5.���� PE
	PIMAGE_DOS_HEADER pDos = GetDosHeader();
	if (pDos->e_magic != IMAGE_DOS_SIGNATURE)
	{
		OutputDebugString(L"��Ч PE �ļ�\n");
		return FALSE;
	}
	// ��ȡ NT ͷ
	PIMAGE_NT_HEADERS pNt = GetNtHeader();
	if (pNt->Signature != IMAGE_NT_SIGNATURE)
	{
		OutputDebugString(L"��Ч PE �ļ�\n");
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
	// ��ȡ����Ŀ¼��
	return GetOptionalHeader()->DataDirectory;
}
PIMAGE_EXPORT_DIRECTORY CPe::GetExportDirectory()
{
	PIMAGE_DATA_DIRECTORY pDir = GetDirectory();
	// ������� RVA
	DWORD Rva = pDir[0].VirtualAddress;
	// �� RVA ת�� FOA
	DWORD Exportoffset = RvaToFoa(Rva);
	// ת���ɵ�����ṹ��
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
		// ��ȡ��������׵�ַ
		PTYPEDATA pData = (PTYPEDATA)(pRelTable + 1);
		// ������ҳ����������
		for (int i = 0; i < dwCount; i++)
		{
			if (pData[i].type == 3)
			{
				// ��ȡ���޸������� 0x402000 -�� hello world
				DWORD* pRelocalData =
					(DWORD*)(RvaToFoa(pRelTable->VirtualAddress + pData[i].offset) +
						m_FileBuff);
				// 0x402000 - 0x400000 + 0x800000
				*pRelocalData = *pRelocalData - oldBase + newBase;
			}
		}
		// �ҵ���һ���ض�λ�Ľṹ��
		pRelTable = (PIMAGE_BASE_RELOCATION)((DWORD)pRelTable +
			pRelTable->SizeOfBlock);
	}
	// ���浽�ļ���
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
	//��һ����Դ�������
	DWORD dwCount = pResTable->NumberOfIdEntries +
		pResTable->NumberOfNamedEntries;
	// ��Դ���
	PIMAGE_RESOURCE_DIRECTORY_ENTRY pOneResEntry =
		(PIMAGE_RESOURCE_DIRECTORY_ENTRY)(pResTable + 1);
	for (int i = 0; i < dwCount; i++)
	{
		if (pOneResEntry[i].NameIsString) //�ַ�����Ϊ ID
		{
			PIMAGE_RESOURCE_DIRECTORY_STRING pString =
				(PIMAGE_RESOURCE_DIRECTORY_STRING)(pOneResEntry->NameOffset
					+ (DWORD)pResTable);
			printf("%s\n", pString->NameString);
		}
		else {
			printf("%d\n", pOneResEntry->Id);
		}
		// �ڶ�����Դ����ʾ������Դ������png��
		PIMAGE_RESOURCE_DIRECTORY pTwoResTable =
			(PIMAGE_RESOURCE_DIRECTORY)(pOneResEntry->OffsetToDirectory +
				(DWORD)pResTable);
		// ��ȡ�����Դ�ж��ٸ�
		DWORD dwCount2 = pTwoResTable->NumberOfIdEntries +
			pTwoResTable->NumberOfNamedEntries;

		// ��Դ���
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
			// �����㣬��Դ��������Ϣ
			PIMAGE_RESOURCE_DIRECTORY pThreeResTable =
				(PIMAGE_RESOURCE_DIRECTORY)(pTwoResEntry->OffsetToDirectory +
					(DWORD)pResTable);
			PIMAGE_RESOURCE_DIRECTORY_ENTRY pThreeResEntry =
				(PIMAGE_RESOURCE_DIRECTORY_ENTRY)(pThreeResTable + 1);
			// ������ָ������
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
	// ��ȡ�����
	PIMAGE_IMPORT_DESCRIPTOR pImportTable = GetImporTable();
	// ���������ж��
	while (pImportTable->Name)
	{
		// ���� dll ����
		char* DllName = (char*)(RvaToFoa(pImportTable->Name) + m_FileBuff);
		printf("DllName: %s \n", DllName);
		// ���� INT ���� IAT
		auto pIAT =
			(PIMAGE_THUNK_DATA)(RvaToFoa(pImportTable->FirstThunk) + m_FileBuff);
		// IAT �ж�����뺯������Ҫ����
		while (pIAT->u1.Function)
		{
			// �ж������Ƶ��룬������ŵ���
			if (pIAT->u1.Ordinal & 0x80000000) //��ŵ���
			{
				printf("\t\t order:%02x \n", pIAT->u1.AddressOfData & 0xFFFF);
			}
			else { // ���Ƶ���
				PIMAGE_IMPORT_BY_NAME pByName =
					(PIMAGE_IMPORT_BY_NAME)(RvaToFoa(pIAT->u1.Function) +
						m_FileBuff);
				printf("\t\t order:%02x \t Fun: %s \n", pByName->Hint, pByName->Name);
			}
			pIAT++;
		}
		// ��һ�������
		pImportTable++;
	}
}
void CPe::ParseExportTable()
{
	PIMAGE_EXPORT_DIRECTORY pExport = GetExportDirectory();
	// ��������
	DWORD dwBase = pExport->Base;
	// ������ dll ����
	char* dllName = (char*)(RvaToFoa(pExport->Name) + m_FileBuff);
	printf("Name:%s\n", dllName);
	// ����ַ��
	DWORD* pEAT =
		(DWORD*)(RvaToFoa(pExport->AddressOfFunctions) + m_FileBuff);
	// ���Ʊ�
	DWORD* pENT =
		(DWORD*)(RvaToFoa(pExport->AddressOfNames) + m_FileBuff);
	// ��ű�
	WORD* pEOT =
		(WORD*)(RvaToFoa(pExport->AddressOfNameOrdinals) + m_FileBuff);
	// �����������к�����ַ����
	for (int i = 0; i < pExport->NumberOfFunctions; i++)
	{
		printf("[%d]:0x%08x \t", i + dwBase, pEAT[0]);
		// ��һ����������Ƿ�������
		for (int j = 0; j < pExport->NumberOfNames; j++)
		{
			if (pEOT[j] == i) // ��ű��е�ֵ�뺯����ַ�±���ͬ���������������
			{
				// ��ȡ��������
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
		// ��ȡ��������׵�ַ
		PTYPEDATA pData = (PTYPEDATA)(pRelTable + 1);
		// ������ҳ����������
		for (int i = 0; i < dwCount; i++)
		{
			// ��ȡ���޸�������
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
		// �ҵ���һ���ض�λ�Ľṹ��
		pRelTable = (PIMAGE_BASE_RELOCATION)((DWORD)pRelTable +
			pRelTable->SizeOfBlock);
	}
}
DWORD CPe::RvaToFoa(DWORD dwRva)
{
	// ����ͷ��
	PIMAGE_SECTION_HEADER pSection = GetSectionHeader();
	// ���θ���
	DWORD SectionSize = GetFileHeader()->NumberOfSections;
	// �ж� Rva �����ĸ�������
	for (int i = 0; i < SectionSize; i++) {
		if (dwRva >= pSection[i].VirtualAddress &&
			dwRva < pSection[i].VirtualAddress + pSection[i].SizeOfRawData)
		{
			// Foa = dwRva - �����ڴ�ƫ�� + �������ļ��е�ƫ��
			return dwRva - pSection[i].VirtualAddress + pSection[i].PointerToRawData;
		}
	}
	return -1;
}
