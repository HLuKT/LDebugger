#pragma once
#include "CDebugger.h"
#include <windows.h>
#include <Dbghelp.h>
#pragma comment(lib,"Dbghelp.lib")
#include <atlstr.h>
using namespace std;
class DbgSymbol
{
public:
	DbgSymbol();
	virtual ~DbgSymbol( );
	void	InitSymbol(HANDLE hProcess);
	// ���Һ�������Ӧ�ĵ�ַ
	static SIZE_T	FindApiAddress(HANDLE hProcess,const char* pszName);
	// ���ҵ�ַ��Ӧ�ĺ�����
	static BOOL	GetSymName(HANDLE hProcess , SIZE_T nAddress /*, CString& strName*/);
};

