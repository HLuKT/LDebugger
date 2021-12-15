#include "DbgSymbol.h"
#include "CDebugger.h"
#include <atlstr.h>

DbgSymbol::DbgSymbol()
{
}



DbgSymbol::~DbgSymbol( )
{
}


void DbgSymbol::InitSymbol(HANDLE hProcess)
{
	DWORD Options = SymGetOptions( );
	Options |= SYMOPT_DEBUG;
	::SymSetOptions(Options);

	::SymInitialize(hProcess ,
					NULL ,
					TRUE
					);
	return;
}
//API�ϵ㡪��Ѱ�Һ�������Ӧ�ĵ�ַ
SIZE_T DbgSymbol::FindApiAddress(HANDLE hProcess,const char* pszName)
{
	DWORD64  dwDisplacement = 0;
	char buffer[sizeof(SYMBOL_INFO)+MAX_SYM_NAME * sizeof(TCHAR)];
	PSYMBOL_INFO pSymbol = (PSYMBOL_INFO)buffer;
	pSymbol->SizeOfStruct = sizeof(SYMBOL_INFO);
	pSymbol->MaxNameLen = MAX_SYM_NAME;
	//�������ֲ�ѯ������Ϣ�������pSymbol��
	if(!SymFromName(hProcess , pszName , pSymbol))
	{
		return 0;
	}
	//���غ�����ַ
	return (SIZE_T)pSymbol->Address;
}

//���ݵ�ַ��ȡ������Ϣ
BOOL DbgSymbol::GetSymName(HANDLE hProcess , SIZE_T nAddress/* , CString& strName*/)
{
	SymInitialize(hProcess, NULL, TRUE);
	DWORD64  dwDisplacement = 0;
	char buffer[sizeof(SYMBOL_INFO)+MAX_SYM_NAME * sizeof(TCHAR)];
	PSYMBOL_INFO pSymbol = (PSYMBOL_INFO)buffer;
	pSymbol->SizeOfStruct = sizeof(SYMBOL_INFO);
	pSymbol->MaxNameLen = MAX_SYM_NAME;
	//���ݵ�ַ��ȡ������Ϣ
	if(!SymFromAddr(hProcess , nAddress , &dwDisplacement , pSymbol))
		return FALSE;
	//strName = pSymbol->Name;
	printf("%s\n", pSymbol->Name);
	return TRUE;
}
