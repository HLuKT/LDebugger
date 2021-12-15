//#include <stdio.h>
//#include <iostream>
//#include <winternl.h>
//#pragma comment(lib,"ntdll.lib")
//#include "CDebugger.h"
//#include "CBreakPoint.h"
//#include "Capstone.h"
//// 系统断点是否触发
//bool m_isSystem = false;
//// 打开产生异常的进程/线程的句柄
//void CDebugger::OpenHandles()
//{
//	m_processHandle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, m_debugEvent.dwProcessId);
//	m_threadHandle = OpenThread(THREAD_ALL_ACCESS, FALSE, m_debugEvent.dwThreadId);
//}
//// 关闭产生异常的进程/线程的句柄
//void CDebugger::CloseHandles()
//{
//	CloseHandle(m_processHandle);
//	CloseHandle(m_threadHandle);
//}
//
//// 框架的第一层
//void CDebugger::StartDebug(LPCSTR pszFile/*目标进程的路径*/)
//{
//    //查找目标进程路径
//    if (pszFile == nullptr)
//    {
//        printf("未找到目标进程!");
//        return;
//    }
//    // 被调试进程信息
//    PROCESS_INFORMATION stcProcInfo = { 0 };
//    STARTUPINFOA stcStartupInfo = { sizeof(STARTUPINFOA) };
//    /* 创建调试进程程 */
//    BOOL bRet = CreateProcessA(
//        pszFile,                                        // 可执行模块路径
//        NULL,                                           // 命令行
//        NULL,                                           // 安全描述符
//        NULL,                                           // 线程属性是否可继承
//        FALSE,                                          // 否从调用进程处继承了句柄
//        DEBUG_ONLY_THIS_PROCESS | CREATE_NEW_CONSOLE,   // 以调试的方式启动
//        NULL,                                           // 新进程的环境块
//        NULL,                                           // 新进程的当前工作路径（当前目录）
//        &stcStartupInfo,                                // 指定进程的主窗口特性
//        &stcProcInfo                                    // 接收新进程的识别信息
//    );
//    if (!bRet)
//    {
//        printf("进程创建失败!");
//    }
//
//    // 如果进程创建成功了，就关闭对应的句柄，防止句柄泄露
//    if (bRet == TRUE)
//    {
//        CloseHandle(stcProcInfo.hThread);
//        CloseHandle(stcProcInfo.hProcess);
//    }
//
//    // 初始化反汇编引擎，用于后续的反汇编操作
//    Capstone::Init();
//
//    /*建立调试循环*/        
//    // 2.等待调式事件
//    while (WaitForDebugEvent(&m_debugEvent, INFINITE))
//    {
//        /*框架的第一层*/
//        // 1.等待调试事件 参数1：接收事件信息的结构体 参数2：等待时长
//        //BOOL dwRet = WaitForDebugEvent(&m_debugEvent, INFINITE);
//        //if (!dwRet)
//        //{
//        //    printf("调试事件发生错误!");
//        //    CloseHandle(stcProcInfo.hProcess);
//        //    CloseHandle(stcProcInfo.hThread);
//        //}
//        // 框架的第二层
//        // 打开对应的进程和线程的句柄
//        OpenHandles();
//        // 第二层框架将调试事件分为两部分来处理
//        switch (m_debugEvent.dwDebugEventCode)
//        {
//        // 第一部分是异常调试事件
//        case EXCEPTION_DEBUG_EVENT:
//            printf("异常调试事件\n");
//            m_continueStatus = DispatchEvent(); //进入到第二层分发事件
//            break;
//
//        // 第二部分是其他调试事件
//        case CREATE_PROCESS_DEBUG_EVENT:// 进程创建事件
//            printf("进程创建\n");
//            m_continueStatus = DebughEvent();
//            break;
//
//        case CREATE_THREAD_DEBUG_EVENT: // 线程创建事件
//            printf("线程创建\n");
//            m_continueStatus = DebughEvent();
//            break;
//
//        case EXIT_PROCESS_DEBUG_EVENT:  // 退出进程事件
//            printf("进程退出\n");
//            m_continueStatus = DebughEvent();
//            break;
//
//        case EXIT_THREAD_DEBUG_EVENT:   // 退出线程事件
//            printf("线程退出\n");
//            m_continueStatus = DebughEvent();
//            break;
//
//        case LOAD_DLL_DEBUG_EVENT:      // 映射DLL事件
//            printf("DLL加载\n");
//            m_continueStatus = DebughEvent();
//            break;
//
//        case UNLOAD_DLL_DEBUG_EVENT:    // 卸载DLL事件 
//            printf("DLL卸载\n");
//            m_continueStatus = DebughEvent();
//            break;
//
//        case OUTPUT_DEBUG_STRING_EVENT: // 调试字符串输出事件
//            printf("调试信息\n");
//            m_continueStatus = DebughEvent();
//            break;
//
//        case RIP_EVENT:                 // RIP事件(内部错误)
//            printf("RIP\n");
//            m_continueStatus = DebughEvent();
//            break;
//        default:
//            break;
//        }
//
//        // 3.提交处理结果
//        bRet = ContinueDebugEvent(
//            m_debugEvent.dwProcessId,           // 调试进程ID,必须从DEBUG_EVNET中获取
//            m_debugEvent.dwThreadId,            // 调试线程ID,必须从DEBUG_EVNET中获取
//            m_continueStatus);                  // 异常是否处理，只对异常有效 
//                                                // 回复调试事件的处理结果,如果不回复,目标进程将会一直处于暂停状态.
//        if (!bRet)
//        {
//            printf("提交处理结果时发生错误!");
//            CloseHandle(stcProcInfo.hProcess);
//            CloseHandle(stcProcInfo.hThread);
//        }
//    } 
//    // 为了防止句柄泄露，应该关闭
//    CloseHandles();
//
//}
////附加活动进程
//bool CDebugger::AttachDebug(DWORD dwPid)
//{
//    //注意此API时常需要以管理员权限运行并获取SeDebug特权后调用方可成功
//    return DebugActiveProcess(dwPid);
//}
//
//// 框架的第二层--异常调试事件
//DWORD CDebugger::DispatchEvent()
//{
//    // 如果是调试器自身设置的异常,那么可以修复,返回DBG_CONTINUE
//    // 如果不是调试器自身设置的异常,那么不能修复,返回DBG_EXCEPTION_NOT_HANDLED
//    switch (m_debugEvent.dwDebugEventCode)
//    {
//    case EXCEPTION_BREAKPOINT: // 软件断点（int3断点）
//    {
//        // 修复断点
//        BreakpointException();
//    }
//    break;
//    case EXCEPTION_SINGLE_STEP: // 硬件断点和TF断点
//    {
//        // 修复断点
//        SingleStepException();
//    }
//    break;
//    case EXCEPTION_ACCESS_VIOLATION:// 内存访问断点
//    {
//        // 修复断点
//        MemoryAccessException();
//    }
//    break;
//    default:
//        /*return DBG_EXCEPTION_NOT_HANDLED;    */break;
//    }
//    return m_continueStatus;
//}
//
//// 框架的第二层--其他调试事件
//DWORD CDebugger::DebughEvent()
//{
//    if (CREATE_PROCESS_DEBUG_EVENT)         // 进程创建事件
//    {
//        CREATE_PROCESS_DEBUG_INFO& Info = m_debugEvent.u.CreateProcessInfo;
//    }
//    else if (CREATE_THREAD_DEBUG_EVENT)     // 线程创建事件
//    {
//        CREATE_THREAD_DEBUG_INFO& Info = m_debugEvent.u.CreateThread;
//    }
//    else if (EXIT_PROCESS_DEBUG_EVENT)      // 退出进程事件
//    {
//        EXIT_PROCESS_DEBUG_INFO& Info = m_debugEvent.u.ExitProcess;
//    }
//    else if (EXIT_THREAD_DEBUG_EVENT)       // 退出线程事件
//    {
//        EXIT_THREAD_DEBUG_INFO& Info = m_debugEvent.u.ExitThread;
//    }
//    else if (LOAD_DLL_DEBUG_EVENT)          // 映射DLL事件
//    {
//        LOAD_DLL_DEBUG_INFO& Info = m_debugEvent.u.LoadDll;
//    }
//    else if (UNLOAD_DLL_DEBUG_EVENT)        // 卸载DLL事件 
//    {
//        UNLOAD_DLL_DEBUG_INFO& Info = m_debugEvent.u.UnloadDll;
//    }
//    else if (OUTPUT_DEBUG_STRING_EVENT)     // 调试字符串输出事件
//    {
//        OUTPUT_DEBUG_STRING_INFO& Info = m_debugEvent.u.DebugString;
//    }
//    else if (RIP_EVENT)                     // RIP事件(内部错误)
//    {
//        RIP_INFO& Info = m_debugEvent.u.RipInfo;
//    }
//    return m_continueStatus;
//}
//
//// 检测进程环境块PEB中的标志以确定进程是否正在被用户模式的调试器调试
////void CDebugger::DebugSetPEB(HANDLE process)
////{
////    PROCESS_BASIC_INFORMATION stcProcInfo;
////    NtQueryInformationProcess(process, ProcessBasicInformation, &stcProcInfo, sizeof(stcProcInfo), NULL);
////    //获取PEB的地址
////    PPEB pPeb = stcProcInfo.PebBaseAddress;
////    DWORD dwSize = 0;
////    // 修改PEB相关字段
////    BYTE value1 = 0;
////    WriteProcessMemory(process, (BYTE*)pPeb + 0x02, &value1, 1, &dwSize);
////    printf("PEB反调试解决\n");
////    m_isSolvePEB = true; // 标志其已经解决
////    return;
////}
//// 框架的第三层--断点异常
//DWORD CDebugger::BreakpointException()
//{
//    // 框架的第三层
//    // 第三层是专门负责修复异常的.
//    // 如果是调试器自身设置的异常,那么可以修复,返回DBG_CONTINUE
//    // 如果不是调试器自身设置的异常,那么不能修复,返回DBG_EXCEPTION_NOT_HANDLED
//    // 1.获取异常类型、发生地址
//    DWORD exceptionCode = m_debugEvent.u.Exception.ExceptionRecord.ExceptionCode;
//    LPVOID exceptionAddr = m_debugEvent.u.Exception.ExceptionRecord.ExceptionAddress;
//    // 2.处理软件断点（int3断点）
//        // ①系统断点发生（其为0则没发生，发生后则作标记
//        if (isSystemPoint)
//        {
//            printf("触发系统OEP断点\n");
//            //m_isSystem = true;
//            isSystemPoint = FALSE;
//            // 注意，在系统断点发生之后在修改PEB的值
//            // 被调试进程在跑之前，系统先检测PEB的BeingDebug值，根据这个来下系统断点
//            // 若之前就修改，系统检测不到，就停不下来
//            //DebugSetPEB(m_processHandle);
//            CBreakPoint::removeBreakpoint_int3(m_processHandle, m_threadHandle, exceptionAddr);
//        }
//       // // 1 条件断点
//       //else if (m_isConditonSet)
//       // {
//       //     bool isFind = CBreakPoint::WhenConditionBreakPoint(m_processHandle, m_threadHandle, m_eax, LPVOID(exceptionAddr));
//       //     // 若满足条件，则打印，修复，继续执行
//       //     if (isFind)
//       //     {
//       //         printf("异常类型: %08X\n 异常地址: %p\n", exceptionCode, exceptionAddr);
//       //         printf("详情: eax=%d 的条件断点发生\n", m_eax);
//       //         m_isConditonSet = false;
//       //     }
//       // }
//        // ③普通软件断点
//        else
//        {
//            printf("触发int3软件断点\n");
//            CBreakPoint::removeBreakpoint_int3(m_processHandle, m_threadHandle, exceptionAddr);
//            // 再下一个TF单步断点
//            CBreakPoint::setBreakpoint_tf(m_threadHandle);
//        }
//    //3.和用户进行交互
//    UserInput();
//    return m_continueStatus;
//}
//
//// 框架的第三层--单步异常
//DWORD CDebugger::SingleStepException()
//{
//    // 框架的第三层
//    // 第三层是专门负责修复异常的.
//    // 如果是调试器自身设置的异常,那么可以修复,返回DBG_CONTINUE
//    // 如果不是调试器自身设置的异常,那么不能修复,返回DBG_EXCEPTION_NOT_HANDLED
//    // 1.获取异常类型、发生地址
//    DWORD ExceptionCode = m_debugEvent.u.Exception.ExceptionRecord.ExceptionCode;
//    LPVOID ExceptionAddr = m_debugEvent.u.Exception.ExceptionRecord.ExceptionAddress;
//    // 2.处理硬件断点和TF断点
//    switch (m_singleStepType)
//    {
//    case CDebugger::Breakpoint_tf:
//        printf("异常类型: %08X\n 异常地址: %p\n", ExceptionCode, ExceptionAddr);
//        printf("触发单步断点\n");
//        break;
//    case CDebugger::Breakpoint_hardExec:
//        printf("异常类型: %08X\n 异常地址: %p\n", ExceptionCode, ExceptionAddr);
//        printf("触发硬件执行断点\n");
//        CBreakPoint::removeBreakpoint_hard(m_threadHandle);
//        //return;
//        break;
//    case CDebugger::Breakpoint_hardRW:
//        printf("异常类型: %08X\n 异常地址: %p\n", ExceptionCode, ExceptionAddr);
//        printf("触发硬件读写断点\n");
//        CBreakPoint::removeBreakpoint_hard(m_threadHandle);
//        break;
//    default:
//        break;
//    }
//    //3.和用户进行交互
//    UserInput();
//    return m_continueStatus;
//}
//
//// 框架的第三层--内存访问异常
//DWORD CDebugger::MemoryAccessException()
//{
//    // 框架的第三层
//    // 第三层是专门负责修复异常的.
//    // 如果是调试器自身设置的异常,那么可以修复,返回DBG_CONTINUE
//    // 如果不是调试器自身设置的异常,那么不能修复,返回DBG_EXCEPTION_NOT_HANDLED
//    // 1.获取异常类型、发生地址
//    DWORD ExceptionCode = m_debugEvent.u.Exception.ExceptionRecord.ExceptionCode;
//    LPVOID ExceptionAddr = m_debugEvent.u.Exception.ExceptionRecord.ExceptionAddress;
//
//    // 表示异信息的EXCEPTION_RECORD结构体将内存访问异常的详细信息保存在数组中
//    // ①第0个元素保存的是内存访问异常的具体异常方式，保存0时表示读取时异常，保存1时表示写入时异常，保存8时表示执行时异常
//    DWORD MemoryAccessExceptionType = m_debugEvent.u.Exception.ExceptionRecord.ExceptionInformation[0];
//    // ②第2个元素保存的是发生异常的线性虚拟地址
//    DWORD MemoryAccessExceptionAddr = m_debugEvent.u.Exception.ExceptionRecord.ExceptionInformation[2];
//    
//    // 2.处理内存断点
//    bool isFind = CBreakPoint::removeBreakpoint_memory(m_processHandle, m_threadHandle, LPVOID(MemoryAccessExceptionAddr));
//    // 如果找到地址，则打印信息，break
//    if (isFind)
//    {
//        printf("\n================================ 异常信息 ==================================\n");
//        printf("异常类型: %08X\n 异常线性虚拟地址: %p\n", ExceptionCode, MemoryAccessExceptionAddr);
//        // 打印具体类型
//        switch (MemoryAccessExceptionType)
//        {
//        case 0:
//            printf("内存读取时异常\n");
//            break;
//        case 1:
//            printf("内存写入时异常\n");
//            break;
//        case 8:
//            printf("内存执行时异常\n");
//            break;
//        default:
//            break;
//        }
//    }
//    // 3.查看EIP位置的反汇编代码
//    Capstone::DisAsm(m_processHandle, ExceptionAddr, 10);
//    // 4.和用户进行交互
//    UserInput();
//    return m_continueStatus;
//}
//
//// 处理用户输入的函数,完成目的3
//void CDebugger::UserInput()
//{
//    // 输出信息,完成目的2
//    //printf("断点在地址 % 08X上触发\n", dbgEvent.u.Exception.ExceptionRecord.ExceptionAddress);
//    // 输出反汇编代码
//    // 输出寄存器信息
//    // 接收用户输入,完成目的3
//    char szCmd[0x10] = { 0 };
//    while (1)
//    {
//        // 1.获取输入的指令
//        scanf_s("%s", szCmd, 0x10);
//        // 软件断点
//        if (!_stricmp(szCmd, "bp"))
//        {
//            // 设置int3软件断点
//            LPVOID addr = 0;
//            scanf_s("%x", &addr);
//            CBreakPoint::setBreakpoint_int3(m_processHandle, addr);
//            m_EternalPointAddr = addr;
//        }
//        // 单步步入
//        else if (!_stricmp(szCmd, "t"))
//        {
//            // 设置TF单步步入断点
//            CBreakPoint::setBreakpoint_tf(m_threadHandle);
//            m_singleStepType = Breakpoint_tf;
//            break;
//        }
//        // 单步步过
//        else if (!_stricmp(szCmd, "p"))
//        {
//            // 设置单步步过断点
//            CBreakPoint::setBreakpoint_tf_int3(m_processHandle, m_threadHandle);
//            // break结束本次循环，取消步过时设下的int3断点
//            break;
//        }
//        // 运行
//        else if (!_stricmp(szCmd, "g"))
//        {
//            // 继续执行，直到运行结束或遇到下一个异常
//            break;
//        }
//        // 硬件执行断点
//        else if (!_stricmp(szCmd, "bae"))
//        {
//            // 获取要设置的地址
//            LPVOID addr = 0;
//            scanf_s("%x", &addr);
//            // 执行断点时，RW = 0，len = 0（RW:0(执行断点,它的len也必须为0））
//            CBreakPoint::setBreakpoint_hardExec(m_threadHandle, (DWORD)addr);
//            m_singleStepType = Breakpoint_hardExec;
//        }
//        //硬件读写断点
//        else if (!strcmp(szCmd, "baw"))
//        {
//            // 获取要设置的地址、类型
//            LPVOID addr = 0;
//            int len = 0;
//            scanf_s("%x", &addr);
//            scanf_s("%d", &len);
//            // 读写断点时，RW = 1（ 1(写) 3(读写））
//            // len:0(1字节), 1（2字节), 2（8字节), 3（4字节)
//            CBreakPoint::setBreakpoint_hardRW(m_threadHandle, (DWORD)addr, len - 1);
//            m_singleStepType = Breakpoint_hardRW;
//        }
//    }
//}