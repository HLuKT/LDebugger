#pragma once
#include <windows.h>
#include <TlHelp32.h>
// �쳣�����Ľ��̵ľ��
//HANDLE m_processHandle = NULL;
//��־�Ĵ�����λ����
typedef union _EFLAG_REGISTER
{
	unsigned int MyEFlag;
	struct
	{
		unsigned int CF : 1;
		unsigned int : 1;
		unsigned int PF : 1;
		unsigned int : 1;
		unsigned int AF : 1;
		unsigned int : 1;
		unsigned int ZF : 1;
		unsigned int SF : 1;
		unsigned int TF : 1;
		unsigned int IF : 1;
		unsigned int DF : 1;
		unsigned int OF : 1;
	}flag;
}EFLAG_REGISTER, * P_EFLAG_REGISTER;

class CDebugger
{
public:
	// ��ܵĵ�һ�㡪���򿪡����ӽ���
	// �򿪱����Խ���
	void StartDebug(LPCSTR filePath);
	// ���ӻ����
	bool AttachDebug(DWORD dwPid);
	// ��ܵĵڶ��㡪����������¼�
	// �쳣�����¼�
	void DispatchEvent();
	// ��ܵĵ����㡪���޸��쳣
	// �޸��쳣
	void DispatchException();
	// ���������¼�
	void ExceptionEvent();
	// �ϵ��쳣
	void BreakpointException();
	// �����쳣
	void SingleStepException();
	// �ڴ�����쳣
	void MemoryAccessException();
	// �û�����
	// �����û�����ĺ���,���Ŀ��3
	void UserInput();
public:
	// �����¼��Ľṹ��
	DEBUG_EVENT m_debugEvent = { 0 };
	// ����Ľ��
	DWORD m_continueStatus = DBG_CONTINUE;	
	// �쳣�������̵߳ľ��
	HANDLE m_threadHandle = NULL;		
	// �쳣�����Ľ��̵ľ��
	HANDLE m_processHandle = NULL;			
	// �򿪽��̾��
	void OpenHandles();
	// �رս��̾��
	void CloseHandles();
	// OEP
	LPVOID OEP;
	// ϵͳ�ϵ��Ƿ񴥷�
	BOOL isSystemPoint = TRUE;
	// ����¼��ɴ��������쳣
	enum Type 
	{ 
		Breakpoint_tf,
		Breakpoint_hardExec,
		Breakpoint_hardRW,
		Breakpoint_memory,
		Breakpoint_condition,
		Breakpoint_int3,
		Breakpoint_CC
	}m_singleStepType;
	// ���öϵ�ĵ�ַ
	LPVOID m_EternalPointAddr = 0;
	// �����ڴ�ϵ��λ��
	LPVOID m_MemoryBreakPointAddr = 0;	
	// ���������ϵ������
	int m_eax = 0;
	// �Ƿ����������ϵ�
	bool m_isConditonPoint = FALSE;
	bool m_isP = FALSE;
	// ���������ϵ��λ��
	LPVOID m_ConditionBreakPointAddr = 0;
	// ��ʾ�Ĵ�����Ϣ
	void ShowRegisterInfo(HANDLE thread);
	// ��ʾ�ڴ���Ϣ
	void ShowMemoryInfo(HANDLE process, DWORD addr, int size);
	// ��ʾջ��Ϣ
	void ShowStackInfo(HANDLE process, DWORD addr, int size);
	// �����Խ�����Ϣ
	PROCESS_INFORMATION m_processInfo = { 0 };
	// ��ʾģ����Ϣ
	void ShowModuleInfo();
	// �޸ļĴ���
	void ModifyRegister(HANDLE thread, char* regis, LPVOID buff);
	// �޸��ڴ�
	void ModifyMemory(HANDLE process, LPVOID addr, char* buff);
	// �޸ķ�������
	void ModifyDisAsm(HANDLE Handle, LPVOID Addr, char asmCode[]);
	// ��������
	void DebugSetPEB(HANDLE process);
	void DebugHookAPI(HANDLE process);
	// �Ƿ�����PEB������
	bool m_isSolvePEB = false;
	DWORD CopyImageBufferToNewBuffer(IN LPVOID pImageBuffer, OUT LPVOID* pNewBuffer);
	BOOL MemeryTOFile(IN LPVOID pMemBuffer, IN size_t size, OUT LPSTR lpszFile);
	DWORD GetImageBassAddress();
	void ReadMemoryBytes(DWORD nAddress, LPBYTE nValue, DWORD nLen);
	void Dump();
	DWORD m_Pid = 0;
	HANDLE m_SymHandle = (HANDLE)0x9999;
	//��������
	BOOL LoadSymbol(CREATE_PROCESS_DEBUG_INFO* pInfo);

};

