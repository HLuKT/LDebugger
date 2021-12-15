#pragma once
#include <windows.h>
#include <TlHelp32.h>
// 异常产生的进程的句柄
//HANDLE m_processHandle = NULL;
//标志寄存器按位解析
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
	// 框架的第一层——打开、附加进程
	// 打开被调试进程
	void StartDebug(LPCSTR filePath);
	// 附加活动进程
	bool AttachDebug(DWORD dwPid);
	// 框架的第二层——处理调试事件
	// 异常调试事件
	void DispatchEvent();
	// 框架的第三层——修复异常
	// 修复异常
	void DispatchException();
	// 其他调试事件
	void ExceptionEvent();
	// 断点异常
	void BreakpointException();
	// 单步异常
	void SingleStepException();
	// 内存访问异常
	void MemoryAccessException();
	// 用户交互
	// 处理用户输入的函数,完成目的3
	void UserInput();
public:
	// 调试事件的结构体
	DEBUG_EVENT m_debugEvent = { 0 };
	// 处理的结果
	DWORD m_continueStatus = DBG_CONTINUE;	
	// 异常产生的线程的句柄
	HANDLE m_threadHandle = NULL;		
	// 异常产生的进程的句柄
	HANDLE m_processHandle = NULL;			
	// 打开进程句柄
	void OpenHandles();
	// 关闭进程句柄
	void CloseHandles();
	// OEP
	LPVOID OEP;
	// 系统断点是否触发
	BOOL isSystemPoint = TRUE;
	// 多个事件可触发单步异常
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
	// 永久断点的地址
	LPVOID m_EternalPointAddr = 0;
	// 设置内存断点的位置
	LPVOID m_MemoryBreakPointAddr = 0;	
	// 设置条件断点的条件
	int m_eax = 0;
	// 是否开启了条件断点
	bool m_isConditonPoint = FALSE;
	bool m_isP = FALSE;
	// 设置条件断点的位置
	LPVOID m_ConditionBreakPointAddr = 0;
	// 显示寄存器信息
	void ShowRegisterInfo(HANDLE thread);
	// 显示内存信息
	void ShowMemoryInfo(HANDLE process, DWORD addr, int size);
	// 显示栈信息
	void ShowStackInfo(HANDLE process, DWORD addr, int size);
	// 被调试进程信息
	PROCESS_INFORMATION m_processInfo = { 0 };
	// 显示模块信息
	void ShowModuleInfo();
	// 修改寄存器
	void ModifyRegister(HANDLE thread, char* regis, LPVOID buff);
	// 修改内存
	void ModifyMemory(HANDLE process, LPVOID addr, char* buff);
	// 修改反汇编代码
	void ModifyDisAsm(HANDLE Handle, LPVOID Addr, char asmCode[]);
	// 反反调试
	void DebugSetPEB(HANDLE process);
	void DebugHookAPI(HANDLE process);
	// 是否解决了PEB反调试
	bool m_isSolvePEB = false;
	DWORD CopyImageBufferToNewBuffer(IN LPVOID pImageBuffer, OUT LPVOID* pNewBuffer);
	BOOL MemeryTOFile(IN LPVOID pMemBuffer, IN size_t size, OUT LPSTR lpszFile);
	DWORD GetImageBassAddress();
	void ReadMemoryBytes(DWORD nAddress, LPBYTE nValue, DWORD nLen);
	void Dump();
	DWORD m_Pid = 0;
	HANDLE m_SymHandle = (HANDLE)0x9999;
	//解析符号
	BOOL LoadSymbol(CREATE_PROCESS_DEBUG_INFO* pInfo);

};

