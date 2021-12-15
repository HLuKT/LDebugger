//#include <stdio.h>
//#include <iostream>
//#include <winternl.h>
//#pragma comment(lib,"ntdll.lib")
//#include "CDebugger.h"
//#include "CBreakPoint.h"
//#include "Capstone.h"
//// ϵͳ�ϵ��Ƿ񴥷�
//bool m_isSystem = false;
//// �򿪲����쳣�Ľ���/�̵߳ľ��
//void CDebugger::OpenHandles()
//{
//	m_processHandle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, m_debugEvent.dwProcessId);
//	m_threadHandle = OpenThread(THREAD_ALL_ACCESS, FALSE, m_debugEvent.dwThreadId);
//}
//// �رղ����쳣�Ľ���/�̵߳ľ��
//void CDebugger::CloseHandles()
//{
//	CloseHandle(m_processHandle);
//	CloseHandle(m_threadHandle);
//}
//
//// ��ܵĵ�һ��
//void CDebugger::StartDebug(LPCSTR pszFile/*Ŀ����̵�·��*/)
//{
//    //����Ŀ�����·��
//    if (pszFile == nullptr)
//    {
//        printf("δ�ҵ�Ŀ�����!");
//        return;
//    }
//    // �����Խ�����Ϣ
//    PROCESS_INFORMATION stcProcInfo = { 0 };
//    STARTUPINFOA stcStartupInfo = { sizeof(STARTUPINFOA) };
//    /* �������Խ��̳� */
//    BOOL bRet = CreateProcessA(
//        pszFile,                                        // ��ִ��ģ��·��
//        NULL,                                           // ������
//        NULL,                                           // ��ȫ������
//        NULL,                                           // �߳������Ƿ�ɼ̳�
//        FALSE,                                          // ��ӵ��ý��̴��̳��˾��
//        DEBUG_ONLY_THIS_PROCESS | CREATE_NEW_CONSOLE,   // �Ե��Եķ�ʽ����
//        NULL,                                           // �½��̵Ļ�����
//        NULL,                                           // �½��̵ĵ�ǰ����·������ǰĿ¼��
//        &stcStartupInfo,                                // ָ�����̵�����������
//        &stcProcInfo                                    // �����½��̵�ʶ����Ϣ
//    );
//    if (!bRet)
//    {
//        printf("���̴���ʧ��!");
//    }
//
//    // ������̴����ɹ��ˣ��͹رն�Ӧ�ľ������ֹ���й¶
//    if (bRet == TRUE)
//    {
//        CloseHandle(stcProcInfo.hThread);
//        CloseHandle(stcProcInfo.hProcess);
//    }
//
//    // ��ʼ����������棬���ں����ķ�������
//    Capstone::Init();
//
//    /*��������ѭ��*/        
//    // 2.�ȴ���ʽ�¼�
//    while (WaitForDebugEvent(&m_debugEvent, INFINITE))
//    {
//        /*��ܵĵ�һ��*/
//        // 1.�ȴ������¼� ����1�������¼���Ϣ�Ľṹ�� ����2���ȴ�ʱ��
//        //BOOL dwRet = WaitForDebugEvent(&m_debugEvent, INFINITE);
//        //if (!dwRet)
//        //{
//        //    printf("�����¼���������!");
//        //    CloseHandle(stcProcInfo.hProcess);
//        //    CloseHandle(stcProcInfo.hThread);
//        //}
//        // ��ܵĵڶ���
//        // �򿪶�Ӧ�Ľ��̺��̵߳ľ��
//        OpenHandles();
//        // �ڶ����ܽ������¼���Ϊ������������
//        switch (m_debugEvent.dwDebugEventCode)
//        {
//        // ��һ�������쳣�����¼�
//        case EXCEPTION_DEBUG_EVENT:
//            printf("�쳣�����¼�\n");
//            m_continueStatus = DispatchEvent(); //���뵽�ڶ���ַ��¼�
//            break;
//
//        // �ڶ����������������¼�
//        case CREATE_PROCESS_DEBUG_EVENT:// ���̴����¼�
//            printf("���̴���\n");
//            m_continueStatus = DebughEvent();
//            break;
//
//        case CREATE_THREAD_DEBUG_EVENT: // �̴߳����¼�
//            printf("�̴߳���\n");
//            m_continueStatus = DebughEvent();
//            break;
//
//        case EXIT_PROCESS_DEBUG_EVENT:  // �˳������¼�
//            printf("�����˳�\n");
//            m_continueStatus = DebughEvent();
//            break;
//
//        case EXIT_THREAD_DEBUG_EVENT:   // �˳��߳��¼�
//            printf("�߳��˳�\n");
//            m_continueStatus = DebughEvent();
//            break;
//
//        case LOAD_DLL_DEBUG_EVENT:      // ӳ��DLL�¼�
//            printf("DLL����\n");
//            m_continueStatus = DebughEvent();
//            break;
//
//        case UNLOAD_DLL_DEBUG_EVENT:    // ж��DLL�¼� 
//            printf("DLLж��\n");
//            m_continueStatus = DebughEvent();
//            break;
//
//        case OUTPUT_DEBUG_STRING_EVENT: // �����ַ�������¼�
//            printf("������Ϣ\n");
//            m_continueStatus = DebughEvent();
//            break;
//
//        case RIP_EVENT:                 // RIP�¼�(�ڲ�����)
//            printf("RIP\n");
//            m_continueStatus = DebughEvent();
//            break;
//        default:
//            break;
//        }
//
//        // 3.�ύ������
//        bRet = ContinueDebugEvent(
//            m_debugEvent.dwProcessId,           // ���Խ���ID,�����DEBUG_EVNET�л�ȡ
//            m_debugEvent.dwThreadId,            // �����߳�ID,�����DEBUG_EVNET�л�ȡ
//            m_continueStatus);                  // �쳣�Ƿ���ֻ���쳣��Ч 
//                                                // �ظ������¼��Ĵ�����,������ظ�,Ŀ����̽���һֱ������ͣ״̬.
//        if (!bRet)
//        {
//            printf("�ύ������ʱ��������!");
//            CloseHandle(stcProcInfo.hProcess);
//            CloseHandle(stcProcInfo.hThread);
//        }
//    } 
//    // Ϊ�˷�ֹ���й¶��Ӧ�ùر�
//    CloseHandles();
//
//}
////���ӻ����
//bool CDebugger::AttachDebug(DWORD dwPid)
//{
//    //ע���APIʱ����Ҫ�Թ���ԱȨ�����в���ȡSeDebug��Ȩ����÷��ɳɹ�
//    return DebugActiveProcess(dwPid);
//}
//
//// ��ܵĵڶ���--�쳣�����¼�
//DWORD CDebugger::DispatchEvent()
//{
//    // ����ǵ������������õ��쳣,��ô�����޸�,����DBG_CONTINUE
//    // ������ǵ������������õ��쳣,��ô�����޸�,����DBG_EXCEPTION_NOT_HANDLED
//    switch (m_debugEvent.dwDebugEventCode)
//    {
//    case EXCEPTION_BREAKPOINT: // ����ϵ㣨int3�ϵ㣩
//    {
//        // �޸��ϵ�
//        BreakpointException();
//    }
//    break;
//    case EXCEPTION_SINGLE_STEP: // Ӳ���ϵ��TF�ϵ�
//    {
//        // �޸��ϵ�
//        SingleStepException();
//    }
//    break;
//    case EXCEPTION_ACCESS_VIOLATION:// �ڴ���ʶϵ�
//    {
//        // �޸��ϵ�
//        MemoryAccessException();
//    }
//    break;
//    default:
//        /*return DBG_EXCEPTION_NOT_HANDLED;    */break;
//    }
//    return m_continueStatus;
//}
//
//// ��ܵĵڶ���--���������¼�
//DWORD CDebugger::DebughEvent()
//{
//    if (CREATE_PROCESS_DEBUG_EVENT)         // ���̴����¼�
//    {
//        CREATE_PROCESS_DEBUG_INFO& Info = m_debugEvent.u.CreateProcessInfo;
//    }
//    else if (CREATE_THREAD_DEBUG_EVENT)     // �̴߳����¼�
//    {
//        CREATE_THREAD_DEBUG_INFO& Info = m_debugEvent.u.CreateThread;
//    }
//    else if (EXIT_PROCESS_DEBUG_EVENT)      // �˳������¼�
//    {
//        EXIT_PROCESS_DEBUG_INFO& Info = m_debugEvent.u.ExitProcess;
//    }
//    else if (EXIT_THREAD_DEBUG_EVENT)       // �˳��߳��¼�
//    {
//        EXIT_THREAD_DEBUG_INFO& Info = m_debugEvent.u.ExitThread;
//    }
//    else if (LOAD_DLL_DEBUG_EVENT)          // ӳ��DLL�¼�
//    {
//        LOAD_DLL_DEBUG_INFO& Info = m_debugEvent.u.LoadDll;
//    }
//    else if (UNLOAD_DLL_DEBUG_EVENT)        // ж��DLL�¼� 
//    {
//        UNLOAD_DLL_DEBUG_INFO& Info = m_debugEvent.u.UnloadDll;
//    }
//    else if (OUTPUT_DEBUG_STRING_EVENT)     // �����ַ�������¼�
//    {
//        OUTPUT_DEBUG_STRING_INFO& Info = m_debugEvent.u.DebugString;
//    }
//    else if (RIP_EVENT)                     // RIP�¼�(�ڲ�����)
//    {
//        RIP_INFO& Info = m_debugEvent.u.RipInfo;
//    }
//    return m_continueStatus;
//}
//
//// �����̻�����PEB�еı�־��ȷ�������Ƿ����ڱ��û�ģʽ�ĵ���������
////void CDebugger::DebugSetPEB(HANDLE process)
////{
////    PROCESS_BASIC_INFORMATION stcProcInfo;
////    NtQueryInformationProcess(process, ProcessBasicInformation, &stcProcInfo, sizeof(stcProcInfo), NULL);
////    //��ȡPEB�ĵ�ַ
////    PPEB pPeb = stcProcInfo.PebBaseAddress;
////    DWORD dwSize = 0;
////    // �޸�PEB����ֶ�
////    BYTE value1 = 0;
////    WriteProcessMemory(process, (BYTE*)pPeb + 0x02, &value1, 1, &dwSize);
////    printf("PEB�����Խ��\n");
////    m_isSolvePEB = true; // ��־���Ѿ����
////    return;
////}
//// ��ܵĵ�����--�ϵ��쳣
//DWORD CDebugger::BreakpointException()
//{
//    // ��ܵĵ�����
//    // ��������ר�Ÿ����޸��쳣��.
//    // ����ǵ������������õ��쳣,��ô�����޸�,����DBG_CONTINUE
//    // ������ǵ������������õ��쳣,��ô�����޸�,����DBG_EXCEPTION_NOT_HANDLED
//    // 1.��ȡ�쳣���͡�������ַ
//    DWORD exceptionCode = m_debugEvent.u.Exception.ExceptionRecord.ExceptionCode;
//    LPVOID exceptionAddr = m_debugEvent.u.Exception.ExceptionRecord.ExceptionAddress;
//    // 2.��������ϵ㣨int3�ϵ㣩
//        // ��ϵͳ�ϵ㷢������Ϊ0��û�������������������
//        if (isSystemPoint)
//        {
//            printf("����ϵͳOEP�ϵ�\n");
//            //m_isSystem = true;
//            isSystemPoint = FALSE;
//            // ע�⣬��ϵͳ�ϵ㷢��֮�����޸�PEB��ֵ
//            // �����Խ�������֮ǰ��ϵͳ�ȼ��PEB��BeingDebugֵ�������������ϵͳ�ϵ�
//            // ��֮ǰ���޸ģ�ϵͳ��ⲻ������ͣ������
//            //DebugSetPEB(m_processHandle);
//            CBreakPoint::removeBreakpoint_int3(m_processHandle, m_threadHandle, exceptionAddr);
//        }
//       // // 1 �����ϵ�
//       //else if (m_isConditonSet)
//       // {
//       //     bool isFind = CBreakPoint::WhenConditionBreakPoint(m_processHandle, m_threadHandle, m_eax, LPVOID(exceptionAddr));
//       //     // ���������������ӡ���޸�������ִ��
//       //     if (isFind)
//       //     {
//       //         printf("�쳣����: %08X\n �쳣��ַ: %p\n", exceptionCode, exceptionAddr);
//       //         printf("����: eax=%d �������ϵ㷢��\n", m_eax);
//       //         m_isConditonSet = false;
//       //     }
//       // }
//        // ����ͨ����ϵ�
//        else
//        {
//            printf("����int3����ϵ�\n");
//            CBreakPoint::removeBreakpoint_int3(m_processHandle, m_threadHandle, exceptionAddr);
//            // ����һ��TF�����ϵ�
//            CBreakPoint::setBreakpoint_tf(m_threadHandle);
//        }
//    //3.���û����н���
//    UserInput();
//    return m_continueStatus;
//}
//
//// ��ܵĵ�����--�����쳣
//DWORD CDebugger::SingleStepException()
//{
//    // ��ܵĵ�����
//    // ��������ר�Ÿ����޸��쳣��.
//    // ����ǵ������������õ��쳣,��ô�����޸�,����DBG_CONTINUE
//    // ������ǵ������������õ��쳣,��ô�����޸�,����DBG_EXCEPTION_NOT_HANDLED
//    // 1.��ȡ�쳣���͡�������ַ
//    DWORD ExceptionCode = m_debugEvent.u.Exception.ExceptionRecord.ExceptionCode;
//    LPVOID ExceptionAddr = m_debugEvent.u.Exception.ExceptionRecord.ExceptionAddress;
//    // 2.����Ӳ���ϵ��TF�ϵ�
//    switch (m_singleStepType)
//    {
//    case CDebugger::Breakpoint_tf:
//        printf("�쳣����: %08X\n �쳣��ַ: %p\n", ExceptionCode, ExceptionAddr);
//        printf("���������ϵ�\n");
//        break;
//    case CDebugger::Breakpoint_hardExec:
//        printf("�쳣����: %08X\n �쳣��ַ: %p\n", ExceptionCode, ExceptionAddr);
//        printf("����Ӳ��ִ�жϵ�\n");
//        CBreakPoint::removeBreakpoint_hard(m_threadHandle);
//        //return;
//        break;
//    case CDebugger::Breakpoint_hardRW:
//        printf("�쳣����: %08X\n �쳣��ַ: %p\n", ExceptionCode, ExceptionAddr);
//        printf("����Ӳ����д�ϵ�\n");
//        CBreakPoint::removeBreakpoint_hard(m_threadHandle);
//        break;
//    default:
//        break;
//    }
//    //3.���û����н���
//    UserInput();
//    return m_continueStatus;
//}
//
//// ��ܵĵ�����--�ڴ�����쳣
//DWORD CDebugger::MemoryAccessException()
//{
//    // ��ܵĵ�����
//    // ��������ר�Ÿ����޸��쳣��.
//    // ����ǵ������������õ��쳣,��ô�����޸�,����DBG_CONTINUE
//    // ������ǵ������������õ��쳣,��ô�����޸�,����DBG_EXCEPTION_NOT_HANDLED
//    // 1.��ȡ�쳣���͡�������ַ
//    DWORD ExceptionCode = m_debugEvent.u.Exception.ExceptionRecord.ExceptionCode;
//    LPVOID ExceptionAddr = m_debugEvent.u.Exception.ExceptionRecord.ExceptionAddress;
//
//    // ��ʾ����Ϣ��EXCEPTION_RECORD�ṹ�彫�ڴ�����쳣����ϸ��Ϣ������������
//    // �ٵ�0��Ԫ�ر�������ڴ�����쳣�ľ����쳣��ʽ������0ʱ��ʾ��ȡʱ�쳣������1ʱ��ʾд��ʱ�쳣������8ʱ��ʾִ��ʱ�쳣
//    DWORD MemoryAccessExceptionType = m_debugEvent.u.Exception.ExceptionRecord.ExceptionInformation[0];
//    // �ڵ�2��Ԫ�ر�����Ƿ����쳣�����������ַ
//    DWORD MemoryAccessExceptionAddr = m_debugEvent.u.Exception.ExceptionRecord.ExceptionInformation[2];
//    
//    // 2.�����ڴ�ϵ�
//    bool isFind = CBreakPoint::removeBreakpoint_memory(m_processHandle, m_threadHandle, LPVOID(MemoryAccessExceptionAddr));
//    // ����ҵ���ַ�����ӡ��Ϣ��break
//    if (isFind)
//    {
//        printf("\n================================ �쳣��Ϣ ==================================\n");
//        printf("�쳣����: %08X\n �쳣���������ַ: %p\n", ExceptionCode, MemoryAccessExceptionAddr);
//        // ��ӡ��������
//        switch (MemoryAccessExceptionType)
//        {
//        case 0:
//            printf("�ڴ��ȡʱ�쳣\n");
//            break;
//        case 1:
//            printf("�ڴ�д��ʱ�쳣\n");
//            break;
//        case 8:
//            printf("�ڴ�ִ��ʱ�쳣\n");
//            break;
//        default:
//            break;
//        }
//    }
//    // 3.�鿴EIPλ�õķ�������
//    Capstone::DisAsm(m_processHandle, ExceptionAddr, 10);
//    // 4.���û����н���
//    UserInput();
//    return m_continueStatus;
//}
//
//// �����û�����ĺ���,���Ŀ��3
//void CDebugger::UserInput()
//{
//    // �����Ϣ,���Ŀ��2
//    //printf("�ϵ��ڵ�ַ % 08X�ϴ���\n", dbgEvent.u.Exception.ExceptionRecord.ExceptionAddress);
//    // �����������
//    // ����Ĵ�����Ϣ
//    // �����û�����,���Ŀ��3
//    char szCmd[0x10] = { 0 };
//    while (1)
//    {
//        // 1.��ȡ�����ָ��
//        scanf_s("%s", szCmd, 0x10);
//        // ����ϵ�
//        if (!_stricmp(szCmd, "bp"))
//        {
//            // ����int3����ϵ�
//            LPVOID addr = 0;
//            scanf_s("%x", &addr);
//            CBreakPoint::setBreakpoint_int3(m_processHandle, addr);
//            m_EternalPointAddr = addr;
//        }
//        // ��������
//        else if (!_stricmp(szCmd, "t"))
//        {
//            // ����TF��������ϵ�
//            CBreakPoint::setBreakpoint_tf(m_threadHandle);
//            m_singleStepType = Breakpoint_tf;
//            break;
//        }
//        // ��������
//        else if (!_stricmp(szCmd, "p"))
//        {
//            // ���õ��������ϵ�
//            CBreakPoint::setBreakpoint_tf_int3(m_processHandle, m_threadHandle);
//            // break��������ѭ����ȡ������ʱ���µ�int3�ϵ�
//            break;
//        }
//        // ����
//        else if (!_stricmp(szCmd, "g"))
//        {
//            // ����ִ�У�ֱ�����н�����������һ���쳣
//            break;
//        }
//        // Ӳ��ִ�жϵ�
//        else if (!_stricmp(szCmd, "bae"))
//        {
//            // ��ȡҪ���õĵ�ַ
//            LPVOID addr = 0;
//            scanf_s("%x", &addr);
//            // ִ�жϵ�ʱ��RW = 0��len = 0��RW:0(ִ�жϵ�,����lenҲ����Ϊ0����
//            CBreakPoint::setBreakpoint_hardExec(m_threadHandle, (DWORD)addr);
//            m_singleStepType = Breakpoint_hardExec;
//        }
//        //Ӳ����д�ϵ�
//        else if (!strcmp(szCmd, "baw"))
//        {
//            // ��ȡҪ���õĵ�ַ������
//            LPVOID addr = 0;
//            int len = 0;
//            scanf_s("%x", &addr);
//            scanf_s("%d", &len);
//            // ��д�ϵ�ʱ��RW = 1�� 1(д) 3(��д����
//            // len:0(1�ֽ�), 1��2�ֽ�), 2��8�ֽ�), 3��4�ֽ�)
//            CBreakPoint::setBreakpoint_hardRW(m_threadHandle, (DWORD)addr, len - 1);
//            m_singleStepType = Breakpoint_hardRW;
//        }
//    }
//}