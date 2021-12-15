#include <stdio.h>
#include <iostream>
#include "CDebugger.h"
#include "CBreakPoint.h"
#include "Capstone.h"
#include "Keystone.h"
#include "Plugin.h"
#include "CPe.h"
#include "Psapi.h"
#include <winternl.h>
#pragma comment(lib,"ntdll.lib")
//目标进程路径
const TCHAR* pszFile = L"E:/Desktop/ConsoleApplication1.exe";

// 打开产生异常的进程/线程的句柄
void CDebugger::OpenHandles()
{
    m_processHandle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, m_debugEvent.dwProcessId);
    m_threadHandle = OpenThread(THREAD_ALL_ACCESS, FALSE, m_debugEvent.dwThreadId);
}
// 关闭产生异常的进程/线程的句柄
void CDebugger::CloseHandles()
{
    CloseHandle(m_processHandle);
    CloseHandle(m_threadHandle);
}

// 框架的第一层
void CDebugger::StartDebug(LPCSTR pszFile/*目标进程的路径*/)
{
    //查找目标进程路径
    if (pszFile == nullptr)
    {
        printf("未找到目标进程!");
        return;
    }
    // 被调试进程信息
    PROCESS_INFORMATION stcProcInfo = { 0 };
    STARTUPINFOA stcStartupInfo = { sizeof(STARTUPINFOA) };
    /* 创建调试进程程 */
    BOOL bRet = CreateProcessA(
        pszFile,                                        // 可执行模块路径
        NULL,                                           // 命令行
        NULL,                                           // 安全描述符
        NULL,                                           // 线程属性是否可继承
        FALSE,                                          // 否从调用进程处继承了句柄
        DEBUG_ONLY_THIS_PROCESS | CREATE_NEW_CONSOLE,   // 以调试的方式启动
        NULL,                                           // 新进程的环境块
        NULL,                                           // 新进程的当前工作路径（当前目录）
        &stcStartupInfo,                                // 指定进程的主窗口特性
        &stcProcInfo                                    // 接收新进程的识别信息
    );
    if (!bRet)
    {
        printf("进程创建失败!");
    }

    // 如果进程创建成功了，就关闭对应的句柄，防止句柄泄露
    if (bRet == TRUE)
    {
        CloseHandle(stcProcInfo.hThread);
        CloseHandle(stcProcInfo.hProcess);
    }

    // 初始化反汇编引擎，用于后续的反汇编操作
    Capstone::Init();
}
//附加活动进程
bool CDebugger::AttachDebug(DWORD dwPid)
{
    // 初始化反汇编引擎，用于后续的反汇编操作
    Capstone::Init();
    //注意此API时常需要以管理员权限运行并获取SeDebug特权后调用方可成功
    return DebugActiveProcess(dwPid);
}

// 框架的第二层--异常调试事件
void CDebugger::DispatchEvent()
{
    BOOL dwRet = 0;
    /*建立调试循环*/
    // 2.等待调式事件
    while (1)
    {
        /*框架的第二层*/
        // 1.等待调试事件 参数1：接收事件信息的结构体 参数2：等待时长
        dwRet = WaitForDebugEvent(&m_debugEvent, INFINITE);
        if (!dwRet)
        {
            printf("调试事件发生错误!");
            CloseHandles();
        }
        // 框架的第二层
        // 打开对应的进程和线程的句柄
        OpenHandles();
        // 第二层框架将调试事件分为两部分来处理
        switch (m_debugEvent.dwDebugEventCode)
        {
            // 第一部分是异常调试事件
        case EXCEPTION_DEBUG_EVENT:
            //printf("异常调试事件\n");
            DispatchException(); //进入到第三层分发事件
            break;

            // 第二部分是其他调试事件
        case CREATE_PROCESS_DEBUG_EVENT:// 进程创建事件
            printf("进程创建\n");
            ExceptionEvent();
            break;

        case CREATE_THREAD_DEBUG_EVENT: // 线程创建事件
            printf("线程创建\n");
            ExceptionEvent();
            break;

        case EXIT_PROCESS_DEBUG_EVENT:  // 退出进程事件
            printf("进程退出\n");
            ExceptionEvent();
            break;

        case EXIT_THREAD_DEBUG_EVENT:   // 退出线程事件
            printf("线程退出\n");
            ExceptionEvent();
            break;

        case LOAD_DLL_DEBUG_EVENT:      // 映射DLL事件
            printf("DLL加载\n");
            ExceptionEvent();
            break;

        case UNLOAD_DLL_DEBUG_EVENT:    // 卸载DLL事件 
            printf("DLL卸载\n");
            ExceptionEvent();
            break;

        case OUTPUT_DEBUG_STRING_EVENT: // 调试字符串输出事件
            printf("调试信息\n");
            ExceptionEvent();
            break;

        case RIP_EVENT:                 // RIP事件(内部错误)
            printf("RIP\n");
            ExceptionEvent();
            break;
        default:
            break;
        }

        // 3.提交处理结果
        dwRet = ContinueDebugEvent(
            m_debugEvent.dwProcessId,           // 调试进程ID,必须从DEBUG_EVNET中获取
            m_debugEvent.dwThreadId,            // 调试线程ID,必须从DEBUG_EVNET中获取
            m_continueStatus);                  // 异常是否处理，只对异常有效 
                                                // 回复调试事件的处理结果,如果不回复,目标进程将会一直处于暂停状态.
        if (!dwRet)
        {
            printf("提交处理结果时发生错误!");
            CloseHandles();
        }
    }
    // 为了防止句柄泄露，应该关闭
    CloseHandles();
}

// 框架的第三层--断点异常
void  CDebugger::DispatchException()
{
    // 如果是调试器自身设置的异常,那么可以修复,返回DBG_CONTINUE
    // 如果不是调试器自身设置的异常,那么不能修复,返回DBG_EXCEPTION_NOT_HANDLED
    switch (m_debugEvent.u.Exception.ExceptionRecord.ExceptionCode)
    {
    case EXCEPTION_BREAKPOINT: // 软件断点（int3断点）
    {
        // 修复断点
        BreakpointException();
    }
    break;
    case EXCEPTION_SINGLE_STEP: // 硬件断点和TF断点
    {
        // 修复断点
        SingleStepException();
        //CBreakPoint::Setint3ForeverBreakPoint(m_processHandle);
        //CBreakPoint::SetmemoryForeverBreakPoint(m_processHandle, m_MemoryBreakPointAddr);
    }
    break;
    case EXCEPTION_ACCESS_VIOLATION:// 内存访问断点
    {
        // 修复断点
        MemoryAccessException();
    }
    break;
    default:
        /*return DBG_EXCEPTION_NOT_HANDLED;    */break;
    }
}

// 框架的第三层--其他调试事件
void CDebugger::ExceptionEvent()
{
    if (CREATE_PROCESS_DEBUG_EVENT)         // 进程创建事件
    {
        OEP = m_debugEvent.u.CreateProcessInfo.lpStartAddress;
        //载入进程的符号表
        CREATE_PROCESS_DEBUG_INFO& Info = m_debugEvent.u.CreateProcessInfo;
        /*CDebugger debugger;
        debugger.*/LoadSymbol(&Info);
    }
    else if (CREATE_THREAD_DEBUG_EVENT)     // 线程创建事件
    {
        CREATE_THREAD_DEBUG_INFO& Info = m_debugEvent.u.CreateThread;
    }
    else if (EXIT_PROCESS_DEBUG_EVENT)      // 退出进程事件
    {
        EXIT_PROCESS_DEBUG_INFO& Info = m_debugEvent.u.ExitProcess;
    }
    else if (EXIT_THREAD_DEBUG_EVENT)       // 退出线程事件
    {
        EXIT_THREAD_DEBUG_INFO& Info = m_debugEvent.u.ExitThread;
    }
    else if (LOAD_DLL_DEBUG_EVENT)          // 映射DLL事件
    {
        LOAD_DLL_DEBUG_INFO& Info = m_debugEvent.u.LoadDll;
    }
    else if (UNLOAD_DLL_DEBUG_EVENT)        // 卸载DLL事件 
    {
        UNLOAD_DLL_DEBUG_INFO& Info = m_debugEvent.u.UnloadDll;
    }
    else if (OUTPUT_DEBUG_STRING_EVENT)     // 调试字符串输出事件
    {
        OUTPUT_DEBUG_STRING_INFO& Info = m_debugEvent.u.DebugString;
    }
    else if (RIP_EVENT)                     // RIP事件(内部错误)
    {
        RIP_INFO& Info = m_debugEvent.u.RipInfo;
    }
    else
    {
        return;
    }
}

// 框架的第三层--断点异常
void CDebugger::BreakpointException()
{

    // 框架的第三层
    // 第三层是专门负责修复异常的.
    // 如果是调试器自身设置的异常,那么可以修复,返回DBG_CONTINUE
    // 如果不是调试器自身设置的异常,那么不能修复,返回DBG_EXCEPTION_NOT_HANDLED
    // 1.获取异常类型、发生地址
    DWORD ExceptionCode = m_debugEvent.u.Exception.ExceptionRecord.ExceptionCode;
    LPVOID ExceptionAddr = m_debugEvent.u.Exception.ExceptionRecord.ExceptionAddress;
    // 2.处理软件断点（int3断点）
    // ①系统断点发生
    if (isSystemPoint)
    {
        //附加时
        if (OEP == 0)
        {
            //设置一个TF断点
            CBreakPoint::setBreakpoint_tf(m_threadHandle);
            isSystemPoint = FALSE;
            return;
        }
        else
        {
            //调试时

            printf("触发系统OEP断点\n");
            isSystemPoint = FALSE;
            // 反反调试
            DebugSetPEB(m_processHandle);
            //hookAPI 反反调试
            DebugHookAPI(m_processHandle);
            CBreakPoint::setBreakpoint_int3(m_processHandle,OEP,FALSE);
        }
        // 3.查看EIP位置的反汇编代码
        Capstone::DisAsm(m_processHandle, ExceptionAddr, 10);
        // 4.和用户进行交互
        UserInput();
    }
    // ②条件断点（通过判断EAX的值将程序断下）
    else if (m_isConditonPoint)
    {
        bool isFind = CBreakPoint::removeBreakpoint_condition(m_processHandle, m_threadHandle, LPVOID(ExceptionAddr), m_eax);
        // 若满足条件，则打印，修复，继续执行
        if (isFind)
        {
            printf("异常类型: %08X\n异常地址: %p\n", ExceptionCode, ExceptionAddr);
            printf("触发 eax = %d 的条件断点\n", m_eax);
            //m_isConditonPoint = FALSE;
            // 再下一个TF单步断点
            CBreakPoint::setBreakpoint_tf(m_threadHandle);
            m_singleStepType = Breakpoint_int3;
            // 3.查看EIP位置的反汇编代码
            Capstone::DisAsm(m_processHandle, ExceptionAddr, 10);
            // 4.和用户进行交互
            UserInput();
        }
    }
    //// ③P指令
    //else if (m_isP)
    //{
    //    printf("触发P指令断点\n");
    //    CBreakPoint::removeBreakpoint_int3(m_processHandle, m_threadHandle, ExceptionAddr);
    //    // 再下一个TF单步断点
    //    CBreakPoint::setBreakpoint_tf(m_threadHandle);
    //    // 3.查看EIP位置的反汇编代码
    //    Capstone::DisAsm(m_processHandle, ExceptionAddr, 10);
    //    // 4.和用户进行交互
    //    UserInput();
    //}
     // ④普通软件断点
    else
    {
        printf("触发int3软件断点\n");
        CBreakPoint::removeBreakpoint_int3(m_processHandle, m_threadHandle, ExceptionAddr);
        // 再下一个TF单步断点
        CBreakPoint::setBreakpoint_tf(m_threadHandle);
        m_singleStepType = Breakpoint_int3;
        // 3.查看EIP位置的反汇编代码
        Capstone::DisAsm(m_processHandle, ExceptionAddr, 10);
        // 4.和用户进行交互
        UserInput();
    }
    //// 3.查看EIP位置的反汇编代码
    //Capstone::DisAsm(m_processHandle, ExceptionAddr, 10);
    //// 4.和用户进行交互
    //UserInput();
}

// 框架的第三层--单步异常
void CDebugger::SingleStepException()
{
    // 框架的第三层
    // 第三层是专门负责修复异常的.
    // 如果是调试器自身设置的异常,那么可以修复,返回DBG_CONTINUE
    // 如果不是调试器自身设置的异常,那么不能修复,返回DBG_EXCEPTION_NOT_HANDLED
    // 1.获取异常类型、发生地址
    DWORD ExceptionCode = m_debugEvent.u.Exception.ExceptionRecord.ExceptionCode;
    LPVOID ExceptionAddr = m_debugEvent.u.Exception.ExceptionRecord.ExceptionAddress;
    // 2.处理硬件断点和TF断点
    switch (m_singleStepType)
    {
    case CDebugger::Breakpoint_tf:
        printf("异常类型: %08X\n异常地址: %p\n", ExceptionCode, ExceptionAddr);
        printf("触发单步断点\n");
        Capstone::DisAsm(m_processHandle, ExceptionAddr, 10);
        // 4.和用户进行交互
        UserInput();
        break;
    case CDebugger::Breakpoint_hardExec:
        printf("异常类型: %08X\n异常地址: %p\n", ExceptionCode, ExceptionAddr);
        printf("触发硬件执行断点\n");
        CBreakPoint::removeBreakpoint_hard(m_threadHandle);
        Capstone::DisAsm(m_processHandle, ExceptionAddr, 10);
        // 4.和用户进行交互
        UserInput();
        break;
    case CDebugger::Breakpoint_hardRW:
        printf("异常类型: %08X\n异常地址: %p\n", ExceptionCode, ExceptionAddr);
        printf("触发硬件读写断点\n");
        CBreakPoint::removeBreakpoint_hard(m_threadHandle);
        Capstone::DisAsm(m_processHandle, ExceptionAddr, 10);
        // 4.和用户进行交互
        UserInput();
        break;
    case CDebugger::Breakpoint_memory:
        // 再设置内存断点
        CBreakPoint::SetmemoryForeverBreakPoint(m_processHandle, m_MemoryBreakPointAddr);
        //VirtualProtectEx(m_processHandle, m_MemoryBreakPointAddr, 1, PAGE_NOACCESS, &dwTempProtect);
        //Capstone::DisAsm(m_processHandle, ExceptionAddr, 10);
        //// 4.和用户进行交互
        //UserInput();
        break;
    case CDebugger::Breakpoint_condition:
        // 再设置条件断点，即INT3软件断点
        CBreakPoint::setBreakpoint_condition(m_processHandle, m_threadHandle, m_ConditionBreakPointAddr, m_eax);
        break;
    case CDebugger::Breakpoint_int3:
        // 再设置条件断点，即INT3软件断点
        CBreakPoint::Setint3ForeverBreakPoint(m_processHandle);
      //  CBreakPoint::setBreakpoint_int3(m_processHandle, m_EternalPointAddr);
        break;
    case CDebugger::Breakpoint_CC:
        CBreakPoint::setBreakpoint_tf(m_threadHandle);
        //CBreakPoint::setBreakpoint_int3(m_processHandle, ExceptionAddr);
        //CBreakPoint::setBreakpoint_tf_int3(m_processHandle, m_threadHandle);
        //Capstone::DisAsm(m_processHandle, ExceptionAddr, 10);
        //// 4.和用户进行交互
        //UserInput();
    default:
        break;
    }
    // 3.查看EIP位置的反汇编代码
    if (int3on == TRUE)
    {
        Capstone::DisAsm(m_processHandle, ExceptionAddr, 10); 
        // 4.和用户进行交互
         UserInput();
    }
    int3on = FALSE;
}

// 框架的第三层--内存访问异常
void CDebugger::MemoryAccessException()
{
    // 框架的第三层
    // 第三层是专门负责修复异常的.
    // 如果是调试器自身设置的异常,那么可以修复,返回DBG_CONTINUE
    // 如果不是调试器自身设置的异常,那么不能修复,返回DBG_EXCEPTION_NOT_HANDLED
    // 1.获取异常类型、发生地址
    DWORD ExceptionCode = m_debugEvent.u.Exception.ExceptionRecord.ExceptionCode;
    LPVOID ExceptionAddr = m_debugEvent.u.Exception.ExceptionRecord.ExceptionAddress;

    // 表示异信息的EXCEPTION_RECORD结构体将内存访问异常的详细信息保存在数组中
    // ①第0个元素保存的是内存访问异常的具体异常方式，保存0时表示读取时异常，保存1时表示写入时异常，保存8时表示执行时异常
    DWORD MemoryAccessExceptionType = m_debugEvent.u.Exception.ExceptionRecord.ExceptionInformation[0];
    // ②第2个元素保存的是发生异常的线性虚拟地址
    DWORD MemoryAccessExceptionAddr = m_debugEvent.u.Exception.ExceptionRecord.ExceptionInformation[1];

    // 2.处理内存断点
    bool isFind = CBreakPoint::removeBreakpoint_memory(m_processHandle, m_threadHandle, LPVOID(MemoryAccessExceptionAddr));
    // 如果找到地址，则打印信息，break
    if (isFind)
    {
        printf("异常类型: %08X\n异常地址: %p\n", ExceptionCode, MemoryAccessExceptionAddr);
        // 打印具体类型
        switch (MemoryAccessExceptionType)
        {
        case 0:
            printf("内存读取时异常\n");
            break;
        case 1:
            printf("内存写入时异常\n");
            break;
        case 8:
            printf("内存执行时异常\n");
            break;
        default:
            break;
        }
        // 再下一个TF单步断点
        CBreakPoint::setBreakpoint_tf(m_threadHandle);
        //m_singleStepType = Breakpoint_memory;
        // 3.查看EIP位置的反汇编代码
        Capstone::DisAsm(m_processHandle, ExceptionAddr, 10);
        // 4.和用户进行交互
        UserInput();
    }
}

// 处理用户输入的函数,完成目的3
void CDebugger::UserInput()
{
    // 输出信息,完成目的2
    //printf("断点在地址 % 08X上触发\n", dbgEvent.u.Exception.ExceptionRecord.ExceptionAddress);
    // 输出反汇编代码
    // 输出寄存器信息
    // 接收用户输入,完成目的3
    char szCmd[0x10] = { 0 };
    while (1)
    {
        // 1.获取输入的指令
        scanf_s("%s", szCmd, 0x10);
        // 软件断点
        if (!_stricmp(szCmd, "bp"))
        {
            // 设置int3软件断点
            LPVOID addr = 0;
            scanf_s("%x", &addr);
            CBreakPoint::setBreakpoint_int3(m_processHandle, addr,TRUE);
            m_EternalPointAddr = addr;
        }
        // 单步步入
        else if (!_stricmp(szCmd, "t"))
        {
            // 设置TF单步步入断点
            CBreakPoint::setBreakpoint_tf(m_threadHandle);
            m_singleStepType = Breakpoint_tf;
            break;
        }
        // 单步步过
        else if (!_stricmp(szCmd, "p"))
        {
            // 设置单步步过断点
            CBreakPoint::setBreakpoint_tf_int3(m_processHandle, m_threadHandle);
            // break结束本次循环，取消步过时设下的int3断点
            m_singleStepType = Breakpoint_CC;
            break;
        }
        // 运行
        else if (!_stricmp(szCmd, "g"))
        {
            // 继续执行，直到运行结束或遇到下一个异常
            break;
        }
        // 硬件执行断点
        else if (!_stricmp(szCmd, "bae"))
        {
            // 获取要设置的地址
            LPVOID addr = 0;
            scanf_s("%x", &addr);
            // 执行断点时，RW = 0，len = 0（RW:0(执行断点,它的len也必须为0））
            CBreakPoint::setBreakpoint_hardExec(m_threadHandle, (DWORD)addr);
            m_singleStepType = Breakpoint_hardExec;
        }
        //硬件读写断点
        else if (!strcmp(szCmd, "baw"))
        {
            // 获取要设置的地址、类型
            LPVOID addr = 0;
            int len = 0;
            scanf_s("%x", &addr);
            scanf_s("%d", &len);
            // 读写断点时，RW = 1（ 1(写) 3(读写））
            // len:0(1字节), 1（2字节), 2（8字节), 3（4字节)
            CBreakPoint::setBreakpoint_hardRW(m_threadHandle, (DWORD)addr, len - 1);
            m_singleStepType = Breakpoint_hardRW;
        }
        // 内存执行断点
        else if (!_stricmp(szCmd, "bme"))
        {
            // 获取要设置的地址
            LPVOID addr = 0;
            scanf_s("%x", &addr);
            CBreakPoint::setBreakpoint_memoryExec(m_processHandle, m_threadHandle, addr, TRUE);
            // 记录下此地址，单步异常时再次设置
            m_MemoryBreakPointAddr = addr;
            m_singleStepType = Breakpoint_memory;
        }
        // 内存读写断点
        else if (!_stricmp(szCmd, "bmw"))
        {
            // 获取要设置的地址
            LPVOID addr = 0;
            scanf_s("%x", &addr);
            CBreakPoint::setBreakpoint_memoryRW(m_processHandle, m_threadHandle, addr, TRUE);
            // 记录下此地址，单步异常时再次设置
            m_MemoryBreakPointAddr = addr;
            m_singleStepType = Breakpoint_memory;
        }
        // 显示寄存器的值 
        else if (!_stricmp(szCmd, "r"))
        {
            // 显示寄存器的值
            ShowRegisterInfo(m_threadHandle);
        }
        // 显示栈信息
        else if (!_stricmp(szCmd, "k"))
        {
            // 查看内存信息
            int addr = 0;
            int size = 0;
            scanf_s("%x %d", &addr, &size);
            ShowStackInfo(m_processHandle, addr, size);
        }
        // 显示内存信息
        else if (!_stricmp(szCmd, "db"))
        {
            // 查看内存信息
            int addr = 0;
            int size = 0;
            scanf_s("%x %d", &addr, &size);
            ShowMemoryInfo(m_processHandle, addr, size);
        }
        // 显示模块信息
        else if (!_stricmp(szCmd, "lm"))
        {
            // 显示模块信息
            ShowModuleInfo();
        }
        // 修改反汇编代码
        else if (!_stricmp(szCmd, "ma"))
        {
            // 修改反汇编代码
            // 获取要设置的地址、类型
            LPVOID addr = 0;
            char buff[0x100] = { 0 };
            scanf_s("%x", &addr);
            gets_s(buff);
            ModifyDisAsm(m_processHandle, addr, buff);
        }
        // 修改内存信息
        else if (!strcmp(szCmd, "mm"))
        {
            // 修改内存
            LPVOID addr = 0;
            char buff[100] = { 0 };
            scanf_s("%x", &addr);
            scanf_s("%x", buff, 100);
            ModifyMemory(m_processHandle, addr, buff);
        }
        // 修改寄存器信息
        else if (!strcmp(szCmd, "mr"))
        {
            // 修改寄存器
            char regis[10] = { 0 };
            LPVOID buff = 0;
            scanf_s("%s", regis, 10);
            scanf_s("%x", &buff);
            ModifyRegister(m_threadHandle, regis, buff);
        }
        // 设置条件断点
        else if (!_stricmp(szCmd, "bu"))
        {
            // 获取要设置的地址、条件
            LPVOID addr = 0;
            int eax = 0;
            scanf_s("%x", &addr);
            scanf_s("%d", &eax);
            CBreakPoint::setBreakpoint_condition(m_processHandle, m_threadHandle, addr, eax);
            m_eax = eax;
            m_isConditonPoint = TRUE;
            m_ConditionBreakPointAddr = addr;
            //m_singleStepType = Breakpoint_condition;
            m_singleStepType = Breakpoint_int3;
        }
        // 查看指定位置的反汇编指令
        else if (!strcmp(szCmd, "s"))
        {
            // 查看反汇编指令
            int addr = 0;
            int lines = 0;
            scanf_s("%x %d", &addr, &lines);
            Capstone::DisAsm(m_processHandle, (LPVOID)addr, lines);
        }
        // 加载插件，运行时
        else if (!strcmp(szCmd, "pg"))
        {
            // 正在运行时调用插件
            Plugin::InitAllPlugin();
        }
        //解析模块导出表导入表
        else if (!strcmp(szCmd, "e"))
        {
            CPe obj;
            obj.ParsePe(pszFile);
            printf("导出表：\n");
            obj.ParseExportTable();
            printf("导入表：\n");
            obj.ParseImportTable();
        }
        //Dump
        else if (!strcmp(szCmd, "dump"))
        {
            Dump();
        }
        // API断点
        else if (!_stricmp(szCmd, "api"))
        {
            // 设置API软件断点
            //int addr = 0;
            char buff[100] = { 0 };
            //scanf_s("%x", &addr);
            scanf_s("%x", buff);
            //char funname[50] = {};
            //funname = DbgSymbol::GetFunctionName(m_processHandle, addr, name);
            CBreakPoint::setBreakpoint_API(m_processHandle, buff);
        }
        //帮助
        else if (!_stricmp(szCmd, "help"))
        {
            printf("单步步入：t\t");
            printf("单步步过：p\t");
            printf("运行：g\n");
            printf("软件断点：bp addr\n");
            printf("硬件执行断点：bae addr\t");
            printf("硬件读写断点：baw addr len\n");
            printf("内存执行断点：bme addr\t");
            printf("内存读写断点：bmw addr\n");
            printf("设置条件断点：bu addr eax\t");
            printf("API断点：api addr name\n");
            printf("解析模块导出表导入表：e\t");
            printf("DUMP：dump\n");
            printf("显示寄存器的值：r\t");
            printf("修改寄存器信息：mr regis buff\n");
            printf("显示栈信息：k addr size\t"); 
            printf("显示内存信息：db addr size\t");
            printf("修改内存信息：mm addr buff\n");
            printf("显示模块信息：lm\t");
            printf("修改反汇编代码：ma addr buff\t");
            printf("查看指定位置的反汇编指令：s addr lines\n");
            printf("加载插件：pg\t");
        }
        else
        {
            printf("输入错误！\n");
        }
    }
}

// 显示寄存器信息
void CDebugger::ShowRegisterInfo(HANDLE thread)
{
    // 1.获取线程环境块
    CONTEXT context = { 0 };
    context.ContextFlags = CONTEXT_ALL;
    GetThreadContext(thread, &context);
    EFLAG_REGISTER EFlag = { 0 };
    EFlag.MyEFlag = context.EFlags;
    printf("=============================== 寄存器信息 =================================\n");
    printf("EAX:%08X  EBX:%08X  ECX:%08X  EDX:%08X\n", context.Eax, context.Ebx, context.Ecx, context.Edx);
    printf("ECS:%08X  EDS:%08X  ESS:%08X  EES:%08X\n", context.SegCs, context.SegDs, context.SegEs, context.SegEs);
    printf("ESI:%08X  EDI:%08X\n", context.Esi, context.Edi);
    printf("EBP:%08X  ESP:%08X\n", context.Ebp, context.Esp);
    printf("EIP:%08X\n", context.Eip);
    printf("CF:%X  PF:%X  AF:%X  ZF:%X  SF:%X  TF:%X  IF:%X  DF:%X  OF:%X  \r\n", 
            EFlag.flag.CF, EFlag.flag.PF, EFlag.flag.AF,EFlag.flag.ZF, EFlag.flag.SF, EFlag.flag.TF, EFlag.flag.IF, EFlag.flag.DF, EFlag.flag.OF);
}
// 显示内存信息
void CDebugger::ShowMemoryInfo(HANDLE process, DWORD addr, int size)
{
    // 1.获取线程环境块
    CONTEXT context = { 0 };
    context.ContextFlags = CONTEXT_ALL;
    GetThreadContext(m_threadHandle, &context); 
    // 获取内存信息
    BYTE buff[512] = { 0 };//获取 esp 中保存的地址
    DWORD dwRead = 0;
    ReadProcessMemory(m_processHandle, LPVOID(addr), buff, 512, &dwRead);
    // 打印内存数据、栈信息
    printf("\n================================= 内存数据信息 ===================================\n");
    for (int i = 0; i < size; i++)
    {
        printf("%08X: %08X\tESP+%2d \n", addr, ((DWORD*)buff)[i], i * 4);
        addr += 4;
    }
}

// 显示栈信息
void CDebugger::ShowStackInfo(HANDLE process, DWORD addr, int size)
{
    // 1.获取线程环境块
    CONTEXT context = { 0 };
    context.ContextFlags = CONTEXT_ALL;
    GetThreadContext(m_threadHandle, &context);
    // 2.获取栈信息
    BYTE buff[512] = { 0 };//获取 esp 中保存的地址
    DWORD dwRead = 0;
    ReadProcessMemory(m_processHandle, (BYTE*)context.Esp, buff, 512, &dwRead);

    // 打印栈信息
    printf("\n================================= 栈信息 ===================================\n");
    for (int i = 0; i < size; i++)
    {
        printf("%08X: %08X\n", addr, ((DWORD*)buff)[i]);
        addr += 4;
    }
}

// 显示模块信息
void CDebugger::ShowModuleInfo()
{
    std::vector<MODULEENTRY32> moduleList;

    // 获取快照句柄（遍历模块时需指定pid
    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, m_processInfo.dwProcessId);
    // 存储模块信息
    MODULEENTRY32 mInfo = { sizeof(MODULEENTRY32) };
    // 遍历模块
    Module32First(hSnap, &mInfo);
    do
    {
        moduleList.push_back(mInfo);
    } while (Module32Next(hSnap, &mInfo));

    printf("基址\t\t大小\n");
    for (auto& i : moduleList)
    {
        printf("%08X\t%08X\n", i.modBaseAddr, i.modBaseSize);
    }
}

// 修改寄存器
void CDebugger::ModifyRegister(HANDLE thread, char* regis, LPVOID buff)
{
    // 获取寄存器环境
    CONTEXT context = { CONTEXT_ALL };
    GetThreadContext(thread, &context);
    // 判断修改的哪个寄存器
    if (!strcmp(regis, "eip"))
    {
printf("不能直接修改EIP\n");
    }
    else if (!strcmp(regis, "eax"))
    {  context.Eax = (DWORD)buff;}
    else if (!strcmp(regis, "ebx"))
    {  context.Ebx = (DWORD)buff;}
    else if (!strcmp(regis, "ecx"))
    {
        context.Ecx = (DWORD)buff;
    }      
    else if (!strcmp(regis, "edx"))
    { 
        context.Edx = (DWORD)buff; 
    }  
    else if (!strcmp(regis, "ecs"))
    { 
        context.SegCs = (DWORD)buff;
    }
    else if (!strcmp(regis, "eds"))
    { 
        context.SegDs = (DWORD)buff;
    }
    else if (!strcmp(regis, "ess"))
    {
        context.SegSs = (DWORD)buff; 
    }       
    else if (!strcmp(regis, "ees"))
    {   
        context.SegEs = (DWORD)buff;
    }      
    else if (!strcmp(regis, "ebp"))
    { 
        context.Ebp = (DWORD)buff;
    }
    else if (!strcmp(regis, "esp"))
    { 
        context.Esp = (DWORD)buff; 
    }       
    else if (!strcmp(regis, "eflags"))
    { 
        context.EFlags = (DWORD)buff;
    }   
    else
    { 
        printf("输入错误\n"); 
    }
    // 修改寄存器
    SetThreadContext(thread, &context);
    // 显示寄存器内容
    ShowRegisterInfo(thread);
}

// 修改内存
void CDebugger::ModifyMemory(HANDLE process, LPVOID addr, char* buff)
{
    WriteProcessMemory(process, addr, buff, strlen(buff), NULL);
    // 显示内存数据
    ShowMemoryInfo(process, (DWORD)addr, 10);
}

// 修改反汇编代码
void CDebugger::ModifyDisAsm(HANDLE process, LPVOID addr, char* buff)
{
    //修改汇编
    /*通过 汇编引擎语句实现即可,如keystone引擎*/
    Keystone::Asm(process, addr, buff);
}

// 反反调试
void CDebugger::DebugSetPEB(HANDLE process)
{
    PROCESS_BASIC_INFORMATION stcProcInfo;
    NtQueryInformationProcess(process, ProcessBasicInformation, &stcProcInfo, sizeof(stcProcInfo), NULL);
    //获取PEB的地址
    PPEB pPeb = stcProcInfo.PebBaseAddress;
    DWORD dwSize = 0;
    // 修改PEB相关字段
    BYTE value1 = 0;
    WriteProcessMemory(process, (BYTE*)pPeb + 0x02, &value1, 1, &dwSize);
    printf("PEB反调试解决\n");
    // 标志其已经解决
    m_isSolvePEB = true;
    return;
}

#define DLLPATH L"..\\HookAPI\\Dll4HookAPI.dll"
void CDebugger::DebugHookAPI(HANDLE process)
{
    // 2.在目标进程中申请空间
    LPVOID lpPathAddr = VirtualAllocEx(
        process,			        // 目标进程句柄
        0,							// 指定申请地址
        wcslen(DLLPATH) * 2 + 2,	// 申请空间大小
        MEM_RESERVE | MEM_COMMIT,	// 内存的状态
        PAGE_READWRITE);			// 内存属性

    // 3.在目标进程中写入Dll路径
    DWORD dwWriteSize = 0;
    WriteProcessMemory(
        process,				    // 目标进程句柄
        lpPathAddr,					// 目标进程地址
        DLLPATH,					// 写入的缓冲区
        wcslen(DLLPATH) * 2 + 2,	// 缓冲区大小
        &dwWriteSize);				// 实际写入大小

    // 4.在目标进程中创建线程
    HANDLE hThread = CreateRemoteThread(
        process,					// 目标进程句柄
        NULL,						// 安全属性
        NULL,						// 栈大小
        (PTHREAD_START_ROUTINE)LoadLibraryW,	// 回调函数
        lpPathAddr,					// 回调函数参数
        NULL,						// 标志
        NULL						// 线程ID
    );

    // 5.等待线程结束
    //WaitForSingleObject(hThread, -1);

    // 6.清理环境
    //VirtualFreeEx(process, lpPathAddr, 0, MEM_RELEASE);
    //CloseHandle(hThread);
    //CloseHandle(process);

    printf("DebugPort反调试解决\n");
    return;
}

CString GetRoute(CString type, CString nFileName)
{

    TCHAR szFileName[MAX_PATH] = { 0 };
    _tcscpy_s(szFileName, MAX_PATH, nFileName);


    OPENFILENAME openFileName = { 0 };
    openFileName.lStructSize = sizeof(OPENFILENAME);
    //打开文件对话框
    openFileName.nMaxFile = MAX_PATH;
    openFileName.lpstrFile = szFileName;
    openFileName.nFilterIndex = 1;
    openFileName.Flags = OFN_PATHMUSTEXIST | OFN_FILEMUSTEXIST | OFN_NOCHANGEDIR;
    openFileName.lpstrFilter = L"可执行文件(*.exe)\0*.exe\0";

    if (type == TEXT("save"))
    {
        if (GetSaveFileName(&openFileName))
        {
            return openFileName.lpstrFile;
        }

    }
    else if (type == TEXT("open"))
    {
        if (GetOpenFileName(&openFileName))
        {
            return openFileName.lpstrFile;
        }
    }

    return CString("");
}
DWORD CDebugger::GetImageBassAddress()
{
    HMODULE nHmodule[255]{};
    DWORD nNeedSize;
    BYTE nProcessBuff[1024]{};

    EnumProcessModules(m_processHandle, nHmodule, 255, &nNeedSize);

    return (DWORD)nHmodule[0];
}
void CDebugger::ReadMemoryBytes(DWORD nAddress, LPBYTE nValue, DWORD nLen)
{
    DWORD nReadSize;
    ReadProcessMemory(m_processHandle, (LPCVOID)nAddress, nValue, nLen, &nReadSize);
}
void CDebugger::Dump()
{

    DWORD nImageBassAddress = GetImageBassAddress();

    DWORD nPeSize = 0;				//PE头
    DWORD nImageSize = 0;			//内存中大小
    DWORD nFileSize = 0;			//文件大小
    DWORD nSectionNum = 0;			//区段数量
    PBYTE nPeHeadData = nullptr;	//PE缓存
    PBYTE nImageBuf = nullptr;		//文件缓存
    FILE* pFile = nullptr;			//写出文件指针
    CString nFilePath;				//保存文件路径

    nPeHeadData = new BYTE[4096]{};

    //读取文件头信息
    ReadMemoryBytes(nImageBassAddress, nPeHeadData, 4096);

    //获取PE信息
    PIMAGE_DOS_HEADER nDosHead = (PIMAGE_DOS_HEADER)nPeHeadData;
    PIMAGE_NT_HEADERS nNtHead = (PIMAGE_NT_HEADERS)(nPeHeadData + nDosHead->e_lfanew);
    PIMAGE_SECTION_HEADER nSecetionHead = IMAGE_FIRST_SECTION(nNtHead);

    //PE头大小
    nPeSize = nNtHead->OptionalHeader.SizeOfHeaders;
    //文件的尺寸
    nImageSize = nNtHead->OptionalHeader.SizeOfImage;
    //区段数量	
    nSectionNum = nNtHead->FileHeader.NumberOfSections;


    //申请exe所需的堆空间
    nImageBuf = new BYTE[nImageSize]{};

    //读取PE数据
    ReadMemoryBytes(nImageBassAddress, nImageBuf, nPeSize);

    nFileSize += nPeSize;
    //读取每个区段的数据
    for (DWORD i = 0; i < nSectionNum; i++)
    {
        ReadMemoryBytes(nImageBassAddress + nSecetionHead[i].VirtualAddress, nImageBuf + nSecetionHead[i].PointerToRawData, nSecetionHead[i].SizeOfRawData);
        nFileSize += nSecetionHead[i].SizeOfRawData;
    }

    //修改文件对齐
    nDosHead = (PIMAGE_DOS_HEADER)nImageBuf;
    nNtHead = (PIMAGE_NT_HEADERS)((DWORD)nImageBuf + nDosHead->e_lfanew);
    nNtHead->OptionalHeader.FileAlignment = nNtHead->OptionalHeader.SectionAlignment;

    CString m_ProName;
    nFilePath = GetRoute(TEXT("save"), TEXT("Dump") + m_ProName);

    USES_CONVERSION;
    std::string s(W2A(nFilePath));
    const char* cstr = s.c_str();
    fopen_s(&pFile, cstr, "wb");
    fwrite(nImageBuf, nFileSize, 1, pFile);
    fclose(pFile);

    delete[] nPeHeadData;
    delete[] nImageBuf;

    printf("保存文件至 %s 成功\n",nFilePath);
}

BOOL CDebugger::LoadSymbol(CREATE_PROCESS_DEBUG_INFO* pInfo) 
{

    //打开进程获得进程句柄
    m_SymHandle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, m_processInfo.dwProcessId);

    //初始化符号处理器
    SymInitialize(m_SymHandle, NULL, FALSE);

    //载入符号文件
    SymLoadModule64(m_SymHandle, pInfo->hFile, NULL, NULL, (DWORD64)pInfo->lpBaseOfImage, 0);

    IMAGEHLP_MODULE64 nIMAGEHLP_MODULE64{};
    nIMAGEHLP_MODULE64.SizeOfStruct = sizeof(IMAGEHLP_MODULE64);
    SymGetModuleInfo64(m_SymHandle, (DWORD64)pInfo->lpBaseOfImage, &nIMAGEHLP_MODULE64);

    return TRUE;
}