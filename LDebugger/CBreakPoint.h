#pragma once
#include <windows.h>
#include "DbgSymbol.h"
#include "Capstone.h"
#include <vector>
using namespace std;
extern BOOL int3on;
// ����ϵ���Ϣ�ṹ��
typedef struct _BREAKPOINTINFO
{
	LPVOID addr = 0;		// ��ַ
	BYTE oldOpcode = 0;		// ԭ����ָ����ڻָ�
	BOOL m_bReset = FALSE;	// �Ƿ���Ҫ����ı�־
} BREAKPOINTINFO, * PBREAKPOINTINFO;

// �ڴ�ϵ���Ϣ�ṹ��
typedef struct _MEMBREAKPOINTINFO
{
	LPVOID addr = 0;		// ��ַ
	DWORD  oldAttribute;	// ԭ���ԣ����ڻָ�
	BOOL m_bReset = FALSE;	// �Ƿ���Ҫ����ı�־
} MEMBREAKPOINTINFO, * PMEMBREAKPOINTINFO;

//���ԼĴ���DR7��λ����Ϣ�ṹ��
typedef struct _DBG_REG7
{
	// �ֲ��ϵ�(L0~3)��ȫ�ֶϵ�(G0~3)�ı��λ
	unsigned L0 : 1;        // ��Dr0����ĵ�ַ���� �ֲ��ϵ�
	unsigned G0 : 1;        // ��Dr0����ĵ�ַ���� ȫ�ֶϵ�
	unsigned L1 : 1;        // ��Dr1����ĵ�ַ���� �ֲ��ϵ�
	unsigned G1 : 1;        // ��Dr1����ĵ�ַ���� ȫ�ֶϵ�
	unsigned L2 : 1;        // ��Dr2����ĵ�ַ���� �ֲ��ϵ�
	unsigned G2 : 1;        // ��Dr2����ĵ�ַ���� ȫ�ֶϵ�
	unsigned L3 : 1;        // ��Dr3����ĵ�ַ���� �ֲ��ϵ�
	unsigned G3 : 1;        // ��Dr3����ĵ�ַ���� ȫ�ֶϵ�
	// LE��GE���Ѿ����á����ڽ���CPUƵ�ʣ��Է���׼ȷ���ϵ��쳣
	unsigned LE : 1;        // �����ֶ�
	unsigned GE : 1;        // �����ֶ�
	unsigned Reserve1 : 3;
	// �������ԼĴ�����־λ�������λΪ1������ָ���޸����ǼĴ���ʱ�ᴥ���쳣
	unsigned GD : 1;        // �����ֶ�
	unsigned Reserve2 : 2;
	// ����Dr0~Dr3��ַ��ָ��λ�õĶϵ�����(RW0~3)��ϵ㳤��(LEN0~3)��״̬��������:
	unsigned RW0 : 2;       // �趨Dr0ָ���ַ�Ķϵ�����
	unsigned LEN0 : 2;      // �趨Dr0ָ���ַ�Ķϵ㳤��
	unsigned RW1 : 2;       // �趨Dr1ָ���ַ�Ķϵ�����
	unsigned LEN1 : 2;      // �趨Dr1ָ���ַ�Ķϵ㳤��
	unsigned RW2 : 2;       // �趨Dr2ָ���ַ�Ķϵ�����
	unsigned LEN2 : 2;      // �趨Dr2ָ���ַ�Ķϵ㳤��
	unsigned RW3 : 2;       // �趨Dr3ָ���ַ�Ķϵ�����
	unsigned LEN3 : 2;      // �趨Dr3ָ���ַ�Ķϵ㳤��
}DBG_REG7, * PDBG_REG7;


class CBreakPoint
{
public:
	/*ʵ�ֵ����ϵ�*/
	//���õ�������ϵ㡪��TF�ϵ�
	static void setBreakpoint_tf(HANDLE thread);
	//���õ��������ϵ�
	static void setBreakpoint_tf_int3(HANDLE process, HANDLE handle);
	/*ʵ������ϵ�*/
	//��������ϵ�
	static void setBreakpoint_int3(HANDLE process, LPVOID addr, BOOL res = TRUE);
	//������������ϵ�
	static BOOL Setint3ForeverBreakPoint(HANDLE process);
	//�Ƴ�����ϵ�
	static void removeBreakpoint_int3(HANDLE process, HANDLE thread, LPVOID addr);
	/*ʵ��Ӳ���ϵ�*/
	//����Ӳ��ִ�жϵ�
	static void setBreakpoint_hardExec(HANDLE thread, DWORD addr);
	//����Ӳ����д�ϵ�
	static void setBreakpoint_hardRW(HANDLE thread, DWORD addr, DWORD len);
	//�Ƴ�Ӳ���ϵ�
	static void removeBreakpoint_hard(HANDLE thread);
	/*ʵ���ڴ�ϵ�*/
	//�����ڴ�ִ�жϵ�
	static void setBreakpoint_memoryExec(HANDLE process, HANDLE thread, LPVOID addr, BOOL res = TRUE);
	//�����ڴ��д�ϵ�
	static void setBreakpoint_memoryRW(HANDLE process, HANDLE thread, LPVOID addr, BOOL res = TRUE);
	//���������ڴ�ϵ�
	static BOOL SetmemoryForeverBreakPoint(HANDLE process, LPVOID addr);
	//�Ƴ��ڴ�ϵ�
	static bool removeBreakpoint_memory(HANDLE process, HANDLE thread, LPVOID addr);
	/*ʵ�������ϵ�*/
	//���������ϵ�
	static void setBreakpoint_condition(HANDLE process, HANDLE thread, LPVOID addr, int eax);
	//�Ƴ������ϵ�
	static bool removeBreakpoint_condition(HANDLE process, HANDLE thread, LPVOID addr, int eax);
	/*ʵ��API�ϵ�*/
	//����API�ϵ�
	static void setBreakpoint_API(HANDLE process, const char* pszApiName);
	//int3����ϵ��б�
	static vector<BREAKPOINTINFO> vec_BreakPointList;
	//�ڴ�ϵ�
	static vector<MEMBREAKPOINTINFO> vec_MemoryBreakPointList;
};

