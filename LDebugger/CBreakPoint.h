#pragma once
#include <windows.h>
#include "DbgSymbol.h"
#include "Capstone.h"
#include <vector>
using namespace std;
extern BOOL int3on;
// 软件断点信息结构体
typedef struct _BREAKPOINTINFO
{
	LPVOID addr = 0;		// 地址
	BYTE oldOpcode = 0;		// 原机器指令，用于恢复
	BOOL m_bReset = FALSE;	// 是否需要重设的标志
} BREAKPOINTINFO, * PBREAKPOINTINFO;

// 内存断点信息结构体
typedef struct _MEMBREAKPOINTINFO
{
	LPVOID addr = 0;		// 地址
	DWORD  oldAttribute;	// 原属性，用于恢复
	BOOL m_bReset = FALSE;	// 是否需要重设的标志
} MEMBREAKPOINTINFO, * PMEMBREAKPOINTINFO;

//调试寄存器DR7的位段信息结构体
typedef struct _DBG_REG7
{
	// 局部断点(L0~3)与全局断点(G0~3)的标记位
	unsigned L0 : 1;        // 对Dr0保存的地址启用 局部断点
	unsigned G0 : 1;        // 对Dr0保存的地址启用 全局断点
	unsigned L1 : 1;        // 对Dr1保存的地址启用 局部断点
	unsigned G1 : 1;        // 对Dr1保存的地址启用 全局断点
	unsigned L2 : 1;        // 对Dr2保存的地址启用 局部断点
	unsigned G2 : 1;        // 对Dr2保存的地址启用 全局断点
	unsigned L3 : 1;        // 对Dr3保存的地址启用 局部断点
	unsigned G3 : 1;        // 对Dr3保存的地址启用 全局断点
	// LE，GE【已经弃用】用于降低CPU频率，以方便准确检测断点异常
	unsigned LE : 1;        // 保留字段
	unsigned GE : 1;        // 保留字段
	unsigned Reserve1 : 3;
	// 保护调试寄存器标志位，如果此位为1，则有指令修改条是寄存器时会触发异常
	unsigned GD : 1;        // 保留字段
	unsigned Reserve2 : 2;
	// 保存Dr0~Dr3地址所指向位置的断点类型(RW0~3)与断点长度(LEN0~3)，状态描述如下:
	unsigned RW0 : 2;       // 设定Dr0指向地址的断点类型
	unsigned LEN0 : 2;      // 设定Dr0指向地址的断点长度
	unsigned RW1 : 2;       // 设定Dr1指向地址的断点类型
	unsigned LEN1 : 2;      // 设定Dr1指向地址的断点长度
	unsigned RW2 : 2;       // 设定Dr2指向地址的断点类型
	unsigned LEN2 : 2;      // 设定Dr2指向地址的断点长度
	unsigned RW3 : 2;       // 设定Dr3指向地址的断点类型
	unsigned LEN3 : 2;      // 设定Dr3指向地址的断点长度
}DBG_REG7, * PDBG_REG7;


class CBreakPoint
{
public:
	/*实现单步断点*/
	//设置单步步入断点——TF断点
	static void setBreakpoint_tf(HANDLE thread);
	//设置单步步过断点
	static void setBreakpoint_tf_int3(HANDLE process, HANDLE handle);
	/*实现软件断点*/
	//设置软件断点
	static void setBreakpoint_int3(HANDLE process, LPVOID addr, BOOL res = TRUE);
	//设置永久软件断点
	static BOOL Setint3ForeverBreakPoint(HANDLE process);
	//移除软件断点
	static void removeBreakpoint_int3(HANDLE process, HANDLE thread, LPVOID addr);
	/*实现硬件断点*/
	//设置硬件执行断点
	static void setBreakpoint_hardExec(HANDLE thread, DWORD addr);
	//设置硬件读写断点
	static void setBreakpoint_hardRW(HANDLE thread, DWORD addr, DWORD len);
	//移除硬件断点
	static void removeBreakpoint_hard(HANDLE thread);
	/*实现内存断点*/
	//设置内存执行断点
	static void setBreakpoint_memoryExec(HANDLE process, HANDLE thread, LPVOID addr, BOOL res = TRUE);
	//设置内存读写断点
	static void setBreakpoint_memoryRW(HANDLE process, HANDLE thread, LPVOID addr, BOOL res = TRUE);
	//设置永久内存断点
	static BOOL SetmemoryForeverBreakPoint(HANDLE process, LPVOID addr);
	//移除内存断点
	static bool removeBreakpoint_memory(HANDLE process, HANDLE thread, LPVOID addr);
	/*实现条件断点*/
	//设置条件断点
	static void setBreakpoint_condition(HANDLE process, HANDLE thread, LPVOID addr, int eax);
	//移除条件断点
	static bool removeBreakpoint_condition(HANDLE process, HANDLE thread, LPVOID addr, int eax);
	/*实现API断点*/
	//设置API断点
	static void setBreakpoint_API(HANDLE process, const char* pszApiName);
	//int3软件断点列表
	static vector<BREAKPOINTINFO> vec_BreakPointList;
	//内存断点
	static vector<MEMBREAKPOINTINFO> vec_MemoryBreakPointList;
};

