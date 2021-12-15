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
//API断点——寻找函数名对应的地址
SIZE_T DbgSymbol::FindApiAddress(HANDLE hProcess,const char* pszName)
{
	DWORD64  dwDisplacement = 0;
	char buffer[sizeof(SYMBOL_INFO)+MAX_SYM_NAME * sizeof(TCHAR)];
	PSYMBOL_INFO pSymbol = (PSYMBOL_INFO)buffer;
	pSymbol->SizeOfStruct = sizeof(SYMBOL_INFO);
	pSymbol->MaxNameLen = MAX_SYM_NAME;
	//根据名字查询符号信息，输出到pSymbol中
	if(!SymFromName(hProcess , pszName , pSymbol))
	{
		return 0;
	}
	//返回函数地址
	return (SIZE_T)pSymbol->Address;
}

//根据地址获取符号信息
BOOL DbgSymbol::GetSymName(HANDLE hProcess , SIZE_T nAddress/* , CString& strName*/)
{
	SymInitialize(hProcess, NULL, TRUE);
	DWORD64  dwDisplacement = 0;
	char buffer[sizeof(SYMBOL_INFO)+MAX_SYM_NAME * sizeof(TCHAR)];
	PSYMBOL_INFO pSymbol = (PSYMBOL_INFO)buffer;
	pSymbol->SizeOfStruct = sizeof(SYMBOL_INFO);
	pSymbol->MaxNameLen = MAX_SYM_NAME;
	//根据地址获取符号信息
	if(!SymFromAddr(hProcess , nAddress , &dwDisplacement , pSymbol))
		return FALSE;
	//strName = pSymbol->Name;
	printf("%s\n", pSymbol->Name);
	return TRUE;
}
