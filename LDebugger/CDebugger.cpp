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
//Ŀ�����·��
const TCHAR* pszFile = L"E:/Desktop/ConsoleApplication1.exe";

// �򿪲����쳣�Ľ���/�̵߳ľ��
void CDebugger::OpenHandles()
{
    m_processHandle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, m_debugEvent.dwProcessId);
    m_threadHandle = OpenThread(THREAD_ALL_ACCESS, FALSE, m_debugEvent.dwThreadId);
}
// �رղ����쳣�Ľ���/�̵߳ľ��
void CDebugger::CloseHandles()
{
    CloseHandle(m_processHandle);
    CloseHandle(m_threadHandle);
}

// ��ܵĵ�һ��
void CDebugger::StartDebug(LPCSTR pszFile/*Ŀ����̵�·��*/)
{
    //����Ŀ�����·��
    if (pszFile == nullptr)
    {
        printf("δ�ҵ�Ŀ�����!");
        return;
    }
    // �����Խ�����Ϣ
    PROCESS_INFORMATION stcProcInfo = { 0 };
    STARTUPINFOA stcStartupInfo = { sizeof(STARTUPINFOA) };
    /* �������Խ��̳� */
    BOOL bRet = CreateProcessA(
        pszFile,                                        // ��ִ��ģ��·��
        NULL,                                           // ������
        NULL,                                           // ��ȫ������
        NULL,                                           // �߳������Ƿ�ɼ̳�
        FALSE,                                          // ��ӵ��ý��̴��̳��˾��
        DEBUG_ONLY_THIS_PROCESS | CREATE_NEW_CONSOLE,   // �Ե��Եķ�ʽ����
        NULL,                                           // �½��̵Ļ�����
        NULL,                                           // �½��̵ĵ�ǰ����·������ǰĿ¼��
        &stcStartupInfo,                                // ָ�����̵�����������
        &stcProcInfo                                    // �����½��̵�ʶ����Ϣ
    );
    if (!bRet)
    {
        printf("���̴���ʧ��!");
    }

    // ������̴����ɹ��ˣ��͹رն�Ӧ�ľ������ֹ���й¶
    if (bRet == TRUE)
    {
        CloseHandle(stcProcInfo.hThread);
        CloseHandle(stcProcInfo.hProcess);
    }

    // ��ʼ����������棬���ں����ķ�������
    Capstone::Init();
}
//���ӻ����
bool CDebugger::AttachDebug(DWORD dwPid)
{
    // ��ʼ����������棬���ں����ķ�������
    Capstone::Init();
    //ע���APIʱ����Ҫ�Թ���ԱȨ�����в���ȡSeDebug��Ȩ����÷��ɳɹ�
    return DebugActiveProcess(dwPid);
}

// ��ܵĵڶ���--�쳣�����¼�
void CDebugger::DispatchEvent()
{
    BOOL dwRet = 0;
    /*��������ѭ��*/
    // 2.�ȴ���ʽ�¼�
    while (1)
    {
        /*��ܵĵڶ���*/
        // 1.�ȴ������¼� ����1�������¼���Ϣ�Ľṹ�� ����2���ȴ�ʱ��
        dwRet = WaitForDebugEvent(&m_debugEvent, INFINITE);
        if (!dwRet)
        {
            printf("�����¼���������!");
            CloseHandles();
        }
        // ��ܵĵڶ���
        // �򿪶�Ӧ�Ľ��̺��̵߳ľ��
        OpenHandles();
        // �ڶ����ܽ������¼���Ϊ������������
        switch (m_debugEvent.dwDebugEventCode)
        {
            // ��һ�������쳣�����¼�
        case EXCEPTION_DEBUG_EVENT:
            //printf("�쳣�����¼�\n");
            DispatchException(); //���뵽������ַ��¼�
            break;

            // �ڶ����������������¼�
        case CREATE_PROCESS_DEBUG_EVENT:// ���̴����¼�
            printf("���̴���\n");
            ExceptionEvent();
            break;

        case CREATE_THREAD_DEBUG_EVENT: // �̴߳����¼�
            printf("�̴߳���\n");
            ExceptionEvent();
            break;

        case EXIT_PROCESS_DEBUG_EVENT:  // �˳������¼�
            printf("�����˳�\n");
            ExceptionEvent();
            break;

        case EXIT_THREAD_DEBUG_EVENT:   // �˳��߳��¼�
            printf("�߳��˳�\n");
            ExceptionEvent();
            break;

        case LOAD_DLL_DEBUG_EVENT:      // ӳ��DLL�¼�
            printf("DLL����\n");
            ExceptionEvent();
            break;

        case UNLOAD_DLL_DEBUG_EVENT:    // ж��DLL�¼� 
            printf("DLLж��\n");
            ExceptionEvent();
            break;

        case OUTPUT_DEBUG_STRING_EVENT: // �����ַ�������¼�
            printf("������Ϣ\n");
            ExceptionEvent();
            break;

        case RIP_EVENT:                 // RIP�¼�(�ڲ�����)
            printf("RIP\n");
            ExceptionEvent();
            break;
        default:
            break;
        }

        // 3.�ύ������
        dwRet = ContinueDebugEvent(
            m_debugEvent.dwProcessId,           // ���Խ���ID,�����DEBUG_EVNET�л�ȡ
            m_debugEvent.dwThreadId,            // �����߳�ID,�����DEBUG_EVNET�л�ȡ
            m_continueStatus);                  // �쳣�Ƿ���ֻ���쳣��Ч 
                                                // �ظ������¼��Ĵ�����,������ظ�,Ŀ����̽���һֱ������ͣ״̬.
        if (!dwRet)
        {
            printf("�ύ������ʱ��������!");
            CloseHandles();
        }
    }
    // Ϊ�˷�ֹ���й¶��Ӧ�ùر�
    CloseHandles();
}

// ��ܵĵ�����--�ϵ��쳣
void  CDebugger::DispatchException()
{
    // ����ǵ������������õ��쳣,��ô�����޸�,����DBG_CONTINUE
    // ������ǵ������������õ��쳣,��ô�����޸�,����DBG_EXCEPTION_NOT_HANDLED
    switch (m_debugEvent.u.Exception.ExceptionRecord.ExceptionCode)
    {
    case EXCEPTION_BREAKPOINT: // ����ϵ㣨int3�ϵ㣩
    {
        // �޸��ϵ�
        BreakpointException();
    }
    break;
    case EXCEPTION_SINGLE_STEP: // Ӳ���ϵ��TF�ϵ�
    {
        // �޸��ϵ�
        SingleStepException();
        //CBreakPoint::Setint3ForeverBreakPoint(m_processHandle);
        //CBreakPoint::SetmemoryForeverBreakPoint(m_processHandle, m_MemoryBreakPointAddr);
    }
    break;
    case EXCEPTION_ACCESS_VIOLATION:// �ڴ���ʶϵ�
    {
        // �޸��ϵ�
        MemoryAccessException();
    }
    break;
    default:
        /*return DBG_EXCEPTION_NOT_HANDLED;    */break;
    }
}

// ��ܵĵ�����--���������¼�
void CDebugger::ExceptionEvent()
{
    if (CREATE_PROCESS_DEBUG_EVENT)         // ���̴����¼�
    {
        OEP = m_debugEvent.u.CreateProcessInfo.lpStartAddress;
        //������̵ķ��ű�
        CREATE_PROCESS_DEBUG_INFO& Info = m_debugEvent.u.CreateProcessInfo;
        /*CDebugger debugger;
        debugger.*/LoadSymbol(&Info);
    }
    else if (CREATE_THREAD_DEBUG_EVENT)     // �̴߳����¼�
    {
        CREATE_THREAD_DEBUG_INFO& Info = m_debugEvent.u.CreateThread;
    }
    else if (EXIT_PROCESS_DEBUG_EVENT)      // �˳������¼�
    {
        EXIT_PROCESS_DEBUG_INFO& Info = m_debugEvent.u.ExitProcess;
    }
    else if (EXIT_THREAD_DEBUG_EVENT)       // �˳��߳��¼�
    {
        EXIT_THREAD_DEBUG_INFO& Info = m_debugEvent.u.ExitThread;
    }
    else if (LOAD_DLL_DEBUG_EVENT)          // ӳ��DLL�¼�
    {
        LOAD_DLL_DEBUG_INFO& Info = m_debugEvent.u.LoadDll;
    }
    else if (UNLOAD_DLL_DEBUG_EVENT)        // ж��DLL�¼� 
    {
        UNLOAD_DLL_DEBUG_INFO& Info = m_debugEvent.u.UnloadDll;
    }
    else if (OUTPUT_DEBUG_STRING_EVENT)     // �����ַ�������¼�
    {
        OUTPUT_DEBUG_STRING_INFO& Info = m_debugEvent.u.DebugString;
    }
    else if (RIP_EVENT)                     // RIP�¼�(�ڲ�����)
    {
        RIP_INFO& Info = m_debugEvent.u.RipInfo;
    }
    else
    {
        return;
    }
}

// ��ܵĵ�����--�ϵ��쳣
void CDebugger::BreakpointException()
{

    // ��ܵĵ�����
    // ��������ר�Ÿ����޸��쳣��.
    // ����ǵ������������õ��쳣,��ô�����޸�,����DBG_CONTINUE
    // ������ǵ������������õ��쳣,��ô�����޸�,����DBG_EXCEPTION_NOT_HANDLED
    // 1.��ȡ�쳣���͡�������ַ
    DWORD ExceptionCode = m_debugEvent.u.Exception.ExceptionRecord.ExceptionCode;
    LPVOID ExceptionAddr = m_debugEvent.u.Exception.ExceptionRecord.ExceptionAddress;
    // 2.��������ϵ㣨int3�ϵ㣩
    // ��ϵͳ�ϵ㷢��
    if (isSystemPoint)
    {
        //����ʱ
        if (OEP == 0)
        {
            //����һ��TF�ϵ�
            CBreakPoint::setBreakpoint_tf(m_threadHandle);
            isSystemPoint = FALSE;
            return;
        }
        else
        {
            //����ʱ

            printf("����ϵͳOEP�ϵ�\n");
            isSystemPoint = FALSE;
            // ��������
            DebugSetPEB(m_processHandle);
            //hookAPI ��������
            DebugHookAPI(m_processHandle);
            CBreakPoint::setBreakpoint_int3(m_processHandle,OEP,FALSE);
        }
        // 3.�鿴EIPλ�õķ�������
        Capstone::DisAsm(m_processHandle, ExceptionAddr, 10);
        // 4.���û����н���
        UserInput();
    }
    // �������ϵ㣨ͨ���ж�EAX��ֵ��������£�
    else if (m_isConditonPoint)
    {
        bool isFind = CBreakPoint::removeBreakpoint_condition(m_processHandle, m_threadHandle, LPVOID(ExceptionAddr), m_eax);
        // ���������������ӡ���޸�������ִ��
        if (isFind)
        {
            printf("�쳣����: %08X\n�쳣��ַ: %p\n", ExceptionCode, ExceptionAddr);
            printf("���� eax = %d �������ϵ�\n", m_eax);
            //m_isConditonPoint = FALSE;
            // ����һ��TF�����ϵ�
            CBreakPoint::setBreakpoint_tf(m_threadHandle);
            m_singleStepType = Breakpoint_int3;
            // 3.�鿴EIPλ�õķ�������
            Capstone::DisAsm(m_processHandle, ExceptionAddr, 10);
            // 4.���û����н���
            UserInput();
        }
    }
    //// ��Pָ��
    //else if (m_isP)
    //{
    //    printf("����Pָ��ϵ�\n");
    //    CBreakPoint::removeBreakpoint_int3(m_processHandle, m_threadHandle, ExceptionAddr);
    //    // ����һ��TF�����ϵ�
    //    CBreakPoint::setBreakpoint_tf(m_threadHandle);
    //    // 3.�鿴EIPλ�õķ�������
    //    Capstone::DisAsm(m_processHandle, ExceptionAddr, 10);
    //    // 4.���û����н���
    //    UserInput();
    //}
     // ����ͨ����ϵ�
    else
    {
        printf("����int3����ϵ�\n");
        CBreakPoint::removeBreakpoint_int3(m_processHandle, m_threadHandle, ExceptionAddr);
        // ����һ��TF�����ϵ�
        CBreakPoint::setBreakpoint_tf(m_threadHandle);
        m_singleStepType = Breakpoint_int3;
        // 3.�鿴EIPλ�õķ�������
        Capstone::DisAsm(m_processHandle, ExceptionAddr, 10);
        // 4.���û����н���
        UserInput();
    }
    //// 3.�鿴EIPλ�õķ�������
    //Capstone::DisAsm(m_processHandle, ExceptionAddr, 10);
    //// 4.���û����н���
    //UserInput();
}

// ��ܵĵ�����--�����쳣
void CDebugger::SingleStepException()
{
    // ��ܵĵ�����
    // ��������ר�Ÿ����޸��쳣��.
    // ����ǵ������������õ��쳣,��ô�����޸�,����DBG_CONTINUE
    // ������ǵ������������õ��쳣,��ô�����޸�,����DBG_EXCEPTION_NOT_HANDLED
    // 1.��ȡ�쳣���͡�������ַ
    DWORD ExceptionCode = m_debugEvent.u.Exception.ExceptionRecord.ExceptionCode;
    LPVOID ExceptionAddr = m_debugEvent.u.Exception.ExceptionRecord.ExceptionAddress;
    // 2.����Ӳ���ϵ��TF�ϵ�
    switch (m_singleStepType)
    {
    case CDebugger::Breakpoint_tf:
        printf("�쳣����: %08X\n�쳣��ַ: %p\n", ExceptionCode, ExceptionAddr);
        printf("���������ϵ�\n");
        Capstone::DisAsm(m_processHandle, ExceptionAddr, 10);
        // 4.���û����н���
        UserInput();
        break;
    case CDebugger::Breakpoint_hardExec:
        printf("�쳣����: %08X\n�쳣��ַ: %p\n", ExceptionCode, ExceptionAddr);
        printf("����Ӳ��ִ�жϵ�\n");
        CBreakPoint::removeBreakpoint_hard(m_threadHandle);
        Capstone::DisAsm(m_processHandle, ExceptionAddr, 10);
        // 4.���û����н���
        UserInput();
        break;
    case CDebugger::Breakpoint_hardRW:
        printf("�쳣����: %08X\n�쳣��ַ: %p\n", ExceptionCode, ExceptionAddr);
        printf("����Ӳ����д�ϵ�\n");
        CBreakPoint::removeBreakpoint_hard(m_threadHandle);
        Capstone::DisAsm(m_processHandle, ExceptionAddr, 10);
        // 4.���û����н���
        UserInput();
        break;
    case CDebugger::Breakpoint_memory:
        // �������ڴ�ϵ�
        CBreakPoint::SetmemoryForeverBreakPoint(m_processHandle, m_MemoryBreakPointAddr);
        //VirtualProtectEx(m_processHandle, m_MemoryBreakPointAddr, 1, PAGE_NOACCESS, &dwTempProtect);
        //Capstone::DisAsm(m_processHandle, ExceptionAddr, 10);
        //// 4.���û����н���
        //UserInput();
        break;
    case CDebugger::Breakpoint_condition:
        // �����������ϵ㣬��INT3����ϵ�
        CBreakPoint::setBreakpoint_condition(m_processHandle, m_threadHandle, m_ConditionBreakPointAddr, m_eax);
        break;
    case CDebugger::Breakpoint_int3:
        // �����������ϵ㣬��INT3����ϵ�
        CBreakPoint::Setint3ForeverBreakPoint(m_processHandle);
      //  CBreakPoint::setBreakpoint_int3(m_processHandle, m_EternalPointAddr);
        break;
    case CDebugger::Breakpoint_CC:
        CBreakPoint::setBreakpoint_tf(m_threadHandle);
        //CBreakPoint::setBreakpoint_int3(m_processHandle, ExceptionAddr);
        //CBreakPoint::setBreakpoint_tf_int3(m_processHandle, m_threadHandle);
        //Capstone::DisAsm(m_processHandle, ExceptionAddr, 10);
        //// 4.���û����н���
        //UserInput();
    default:
        break;
    }
    // 3.�鿴EIPλ�õķ�������
    if (int3on == TRUE)
    {
        Capstone::DisAsm(m_processHandle, ExceptionAddr, 10); 
        // 4.���û����н���
         UserInput();
    }
    int3on = FALSE;
}

// ��ܵĵ�����--�ڴ�����쳣
void CDebugger::MemoryAccessException()
{
    // ��ܵĵ�����
    // ��������ר�Ÿ����޸��쳣��.
    // ����ǵ������������õ��쳣,��ô�����޸�,����DBG_CONTINUE
    // ������ǵ������������õ��쳣,��ô�����޸�,����DBG_EXCEPTION_NOT_HANDLED
    // 1.��ȡ�쳣���͡�������ַ
    DWORD ExceptionCode = m_debugEvent.u.Exception.ExceptionRecord.ExceptionCode;
    LPVOID ExceptionAddr = m_debugEvent.u.Exception.ExceptionRecord.ExceptionAddress;

    // ��ʾ����Ϣ��EXCEPTION_RECORD�ṹ�彫�ڴ�����쳣����ϸ��Ϣ������������
    // �ٵ�0��Ԫ�ر�������ڴ�����쳣�ľ����쳣��ʽ������0ʱ��ʾ��ȡʱ�쳣������1ʱ��ʾд��ʱ�쳣������8ʱ��ʾִ��ʱ�쳣
    DWORD MemoryAccessExceptionType = m_debugEvent.u.Exception.ExceptionRecord.ExceptionInformation[0];
    // �ڵ�2��Ԫ�ر�����Ƿ����쳣�����������ַ
    DWORD MemoryAccessExceptionAddr = m_debugEvent.u.Exception.ExceptionRecord.ExceptionInformation[1];

    // 2.�����ڴ�ϵ�
    bool isFind = CBreakPoint::removeBreakpoint_memory(m_processHandle, m_threadHandle, LPVOID(MemoryAccessExceptionAddr));
    // ����ҵ���ַ�����ӡ��Ϣ��break
    if (isFind)
    {
        printf("�쳣����: %08X\n�쳣��ַ: %p\n", ExceptionCode, MemoryAccessExceptionAddr);
        // ��ӡ��������
        switch (MemoryAccessExceptionType)
        {
        case 0:
            printf("�ڴ��ȡʱ�쳣\n");
            break;
        case 1:
            printf("�ڴ�д��ʱ�쳣\n");
            break;
        case 8:
            printf("�ڴ�ִ��ʱ�쳣\n");
            break;
        default:
            break;
        }
        // ����һ��TF�����ϵ�
        CBreakPoint::setBreakpoint_tf(m_threadHandle);
        //m_singleStepType = Breakpoint_memory;
        // 3.�鿴EIPλ�õķ�������
        Capstone::DisAsm(m_processHandle, ExceptionAddr, 10);
        // 4.���û����н���
        UserInput();
    }
}

// �����û�����ĺ���,���Ŀ��3
void CDebugger::UserInput()
{
    // �����Ϣ,���Ŀ��2
    //printf("�ϵ��ڵ�ַ % 08X�ϴ���\n", dbgEvent.u.Exception.ExceptionRecord.ExceptionAddress);
    // �����������
    // ����Ĵ�����Ϣ
    // �����û�����,���Ŀ��3
    char szCmd[0x10] = { 0 };
    while (1)
    {
        // 1.��ȡ�����ָ��
        scanf_s("%s", szCmd, 0x10);
        // ����ϵ�
        if (!_stricmp(szCmd, "bp"))
        {
            // ����int3����ϵ�
            LPVOID addr = 0;
            scanf_s("%x", &addr);
            CBreakPoint::setBreakpoint_int3(m_processHandle, addr,TRUE);
            m_EternalPointAddr = addr;
        }
        // ��������
        else if (!_stricmp(szCmd, "t"))
        {
            // ����TF��������ϵ�
            CBreakPoint::setBreakpoint_tf(m_threadHandle);
            m_singleStepType = Breakpoint_tf;
            break;
        }
        // ��������
        else if (!_stricmp(szCmd, "p"))
        {
            // ���õ��������ϵ�
            CBreakPoint::setBreakpoint_tf_int3(m_processHandle, m_threadHandle);
            // break��������ѭ����ȡ������ʱ���µ�int3�ϵ�
            m_singleStepType = Breakpoint_CC;
            break;
        }
        // ����
        else if (!_stricmp(szCmd, "g"))
        {
            // ����ִ�У�ֱ�����н�����������һ���쳣
            break;
        }
        // Ӳ��ִ�жϵ�
        else if (!_stricmp(szCmd, "bae"))
        {
            // ��ȡҪ���õĵ�ַ
            LPVOID addr = 0;
            scanf_s("%x", &addr);
            // ִ�жϵ�ʱ��RW = 0��len = 0��RW:0(ִ�жϵ�,����lenҲ����Ϊ0����
            CBreakPoint::setBreakpoint_hardExec(m_threadHandle, (DWORD)addr);
            m_singleStepType = Breakpoint_hardExec;
        }
        //Ӳ����д�ϵ�
        else if (!strcmp(szCmd, "baw"))
        {
            // ��ȡҪ���õĵ�ַ������
            LPVOID addr = 0;
            int len = 0;
            scanf_s("%x", &addr);
            scanf_s("%d", &len);
            // ��д�ϵ�ʱ��RW = 1�� 1(д) 3(��д����
            // len:0(1�ֽ�), 1��2�ֽ�), 2��8�ֽ�), 3��4�ֽ�)
            CBreakPoint::setBreakpoint_hardRW(m_threadHandle, (DWORD)addr, len - 1);
            m_singleStepType = Breakpoint_hardRW;
        }
        // �ڴ�ִ�жϵ�
        else if (!_stricmp(szCmd, "bme"))
        {
            // ��ȡҪ���õĵ�ַ
            LPVOID addr = 0;
            scanf_s("%x", &addr);
            CBreakPoint::setBreakpoint_memoryExec(m_processHandle, m_threadHandle, addr, TRUE);
            // ��¼�´˵�ַ�������쳣ʱ�ٴ�����
            m_MemoryBreakPointAddr = addr;
            m_singleStepType = Breakpoint_memory;
        }
        // �ڴ��д�ϵ�
        else if (!_stricmp(szCmd, "bmw"))
        {
            // ��ȡҪ���õĵ�ַ
            LPVOID addr = 0;
            scanf_s("%x", &addr);
            CBreakPoint::setBreakpoint_memoryRW(m_processHandle, m_threadHandle, addr, TRUE);
            // ��¼�´˵�ַ�������쳣ʱ�ٴ�����
            m_MemoryBreakPointAddr = addr;
            m_singleStepType = Breakpoint_memory;
        }
        // ��ʾ�Ĵ�����ֵ 
        else if (!_stricmp(szCmd, "r"))
        {
            // ��ʾ�Ĵ�����ֵ
            ShowRegisterInfo(m_threadHandle);
        }
        // ��ʾջ��Ϣ
        else if (!_stricmp(szCmd, "k"))
        {
            // �鿴�ڴ���Ϣ
            int addr = 0;
            int size = 0;
            scanf_s("%x %d", &addr, &size);
            ShowStackInfo(m_processHandle, addr, size);
        }
        // ��ʾ�ڴ���Ϣ
        else if (!_stricmp(szCmd, "db"))
        {
            // �鿴�ڴ���Ϣ
            int addr = 0;
            int size = 0;
            scanf_s("%x %d", &addr, &size);
            ShowMemoryInfo(m_processHandle, addr, size);
        }
        // ��ʾģ����Ϣ
        else if (!_stricmp(szCmd, "lm"))
        {
            // ��ʾģ����Ϣ
            ShowModuleInfo();
        }
        // �޸ķ�������
        else if (!_stricmp(szCmd, "ma"))
        {
            // �޸ķ�������
            // ��ȡҪ���õĵ�ַ������
            LPVOID addr = 0;
            char buff[0x100] = { 0 };
            scanf_s("%x", &addr);
            gets_s(buff);
            ModifyDisAsm(m_processHandle, addr, buff);
        }
        // �޸��ڴ���Ϣ
        else if (!strcmp(szCmd, "mm"))
        {
            // �޸��ڴ�
            LPVOID addr = 0;
            char buff[100] = { 0 };
            scanf_s("%x", &addr);
            scanf_s("%x", buff, 100);
            ModifyMemory(m_processHandle, addr, buff);
        }
        // �޸ļĴ�����Ϣ
        else if (!strcmp(szCmd, "mr"))
        {
            // �޸ļĴ���
            char regis[10] = { 0 };
            LPVOID buff = 0;
            scanf_s("%s", regis, 10);
            scanf_s("%x", &buff);
            ModifyRegister(m_threadHandle, regis, buff);
        }
        // ���������ϵ�
        else if (!_stricmp(szCmd, "bu"))
        {
            // ��ȡҪ���õĵ�ַ������
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
        // �鿴ָ��λ�õķ����ָ��
        else if (!strcmp(szCmd, "s"))
        {
            // �鿴�����ָ��
            int addr = 0;
            int lines = 0;
            scanf_s("%x %d", &addr, &lines);
            Capstone::DisAsm(m_processHandle, (LPVOID)addr, lines);
        }
        // ���ز��������ʱ
        else if (!strcmp(szCmd, "pg"))
        {
            // ��������ʱ���ò��
            Plugin::InitAllPlugin();
        }
        //����ģ�鵼�������
        else if (!strcmp(szCmd, "e"))
        {
            CPe obj;
            obj.ParsePe(pszFile);
            printf("������\n");
            obj.ParseExportTable();
            printf("�����\n");
            obj.ParseImportTable();
        }
        //Dump
        else if (!strcmp(szCmd, "dump"))
        {
            Dump();
        }
        // API�ϵ�
        else if (!_stricmp(szCmd, "api"))
        {
            // ����API����ϵ�
            //int addr = 0;
            char buff[100] = { 0 };
            //scanf_s("%x", &addr);
            scanf_s("%x", buff);
            //char funname[50] = {};
            //funname = DbgSymbol::GetFunctionName(m_processHandle, addr, name);
            CBreakPoint::setBreakpoint_API(m_processHandle, buff);
        }
        //����
        else if (!_stricmp(szCmd, "help"))
        {
            printf("�������룺t\t");
            printf("����������p\t");
            printf("���У�g\n");
            printf("����ϵ㣺bp addr\n");
            printf("Ӳ��ִ�жϵ㣺bae addr\t");
            printf("Ӳ����д�ϵ㣺baw addr len\n");
            printf("�ڴ�ִ�жϵ㣺bme addr\t");
            printf("�ڴ��д�ϵ㣺bmw addr\n");
            printf("���������ϵ㣺bu addr eax\t");
            printf("API�ϵ㣺api addr name\n");
            printf("����ģ�鵼�������e\t");
            printf("DUMP��dump\n");
            printf("��ʾ�Ĵ�����ֵ��r\t");
            printf("�޸ļĴ�����Ϣ��mr regis buff\n");
            printf("��ʾջ��Ϣ��k addr size\t"); 
            printf("��ʾ�ڴ���Ϣ��db addr size\t");
            printf("�޸��ڴ���Ϣ��mm addr buff\n");
            printf("��ʾģ����Ϣ��lm\t");
            printf("�޸ķ������룺ma addr buff\t");
            printf("�鿴ָ��λ�õķ����ָ�s addr lines\n");
            printf("���ز����pg\t");
        }
        else
        {
            printf("�������\n");
        }
    }
}

// ��ʾ�Ĵ�����Ϣ
void CDebugger::ShowRegisterInfo(HANDLE thread)
{
    // 1.��ȡ�̻߳�����
    CONTEXT context = { 0 };
    context.ContextFlags = CONTEXT_ALL;
    GetThreadContext(thread, &context);
    EFLAG_REGISTER EFlag = { 0 };
    EFlag.MyEFlag = context.EFlags;
    printf("=============================== �Ĵ�����Ϣ =================================\n");
    printf("EAX:%08X  EBX:%08X  ECX:%08X  EDX:%08X\n", context.Eax, context.Ebx, context.Ecx, context.Edx);
    printf("ECS:%08X  EDS:%08X  ESS:%08X  EES:%08X\n", context.SegCs, context.SegDs, context.SegEs, context.SegEs);
    printf("ESI:%08X  EDI:%08X\n", context.Esi, context.Edi);
    printf("EBP:%08X  ESP:%08X\n", context.Ebp, context.Esp);
    printf("EIP:%08X\n", context.Eip);
    printf("CF:%X  PF:%X  AF:%X  ZF:%X  SF:%X  TF:%X  IF:%X  DF:%X  OF:%X  \r\n", 
            EFlag.flag.CF, EFlag.flag.PF, EFlag.flag.AF,EFlag.flag.ZF, EFlag.flag.SF, EFlag.flag.TF, EFlag.flag.IF, EFlag.flag.DF, EFlag.flag.OF);
}
// ��ʾ�ڴ���Ϣ
void CDebugger::ShowMemoryInfo(HANDLE process, DWORD addr, int size)
{
    // 1.��ȡ�̻߳�����
    CONTEXT context = { 0 };
    context.ContextFlags = CONTEXT_ALL;
    GetThreadContext(m_threadHandle, &context); 
    // ��ȡ�ڴ���Ϣ
    BYTE buff[512] = { 0 };//��ȡ esp �б���ĵ�ַ
    DWORD dwRead = 0;
    ReadProcessMemory(m_processHandle, LPVOID(addr), buff, 512, &dwRead);
    // ��ӡ�ڴ����ݡ�ջ��Ϣ
    printf("\n================================= �ڴ�������Ϣ ===================================\n");
    for (int i = 0; i < size; i++)
    {
        printf("%08X: %08X\tESP+%2d \n", addr, ((DWORD*)buff)[i], i * 4);
        addr += 4;
    }
}

// ��ʾջ��Ϣ
void CDebugger::ShowStackInfo(HANDLE process, DWORD addr, int size)
{
    // 1.��ȡ�̻߳�����
    CONTEXT context = { 0 };
    context.ContextFlags = CONTEXT_ALL;
    GetThreadContext(m_threadHandle, &context);
    // 2.��ȡջ��Ϣ
    BYTE buff[512] = { 0 };//��ȡ esp �б���ĵ�ַ
    DWORD dwRead = 0;
    ReadProcessMemory(m_processHandle, (BYTE*)context.Esp, buff, 512, &dwRead);

    // ��ӡջ��Ϣ
    printf("\n================================= ջ��Ϣ ===================================\n");
    for (int i = 0; i < size; i++)
    {
        printf("%08X: %08X\n", addr, ((DWORD*)buff)[i]);
        addr += 4;
    }
}

// ��ʾģ����Ϣ
void CDebugger::ShowModuleInfo()
{
    std::vector<MODULEENTRY32> moduleList;

    // ��ȡ���վ��������ģ��ʱ��ָ��pid
    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, m_processInfo.dwProcessId);
    // �洢ģ����Ϣ
    MODULEENTRY32 mInfo = { sizeof(MODULEENTRY32) };
    // ����ģ��
    Module32First(hSnap, &mInfo);
    do
    {
        moduleList.push_back(mInfo);
    } while (Module32Next(hSnap, &mInfo));

    printf("��ַ\t\t��С\n");
    for (auto& i : moduleList)
    {
        printf("%08X\t%08X\n", i.modBaseAddr, i.modBaseSize);
    }
}

// �޸ļĴ���
void CDebugger::ModifyRegister(HANDLE thread, char* regis, LPVOID buff)
{
    // ��ȡ�Ĵ�������
    CONTEXT context = { CONTEXT_ALL };
    GetThreadContext(thread, &context);
    // �ж��޸ĵ��ĸ��Ĵ���
    if (!strcmp(regis, "eip"))
    {
printf("����ֱ���޸�EIP\n");
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
        printf("�������\n"); 
    }
    // �޸ļĴ���
    SetThreadContext(thread, &context);
    // ��ʾ�Ĵ�������
    ShowRegisterInfo(thread);
}

// �޸��ڴ�
void CDebugger::ModifyMemory(HANDLE process, LPVOID addr, char* buff)
{
    WriteProcessMemory(process, addr, buff, strlen(buff), NULL);
    // ��ʾ�ڴ�����
    ShowMemoryInfo(process, (DWORD)addr, 10);
}

// �޸ķ�������
void CDebugger::ModifyDisAsm(HANDLE process, LPVOID addr, char* buff)
{
    //�޸Ļ��
    /*ͨ�� ����������ʵ�ּ���,��keystone����*/
    Keystone::Asm(process, addr, buff);
}

// ��������
void CDebugger::DebugSetPEB(HANDLE process)
{
    PROCESS_BASIC_INFORMATION stcProcInfo;
    NtQueryInformationProcess(process, ProcessBasicInformation, &stcProcInfo, sizeof(stcProcInfo), NULL);
    //��ȡPEB�ĵ�ַ
    PPEB pPeb = stcProcInfo.PebBaseAddress;
    DWORD dwSize = 0;
    // �޸�PEB����ֶ�
    BYTE value1 = 0;
    WriteProcessMemory(process, (BYTE*)pPeb + 0x02, &value1, 1, &dwSize);
    printf("PEB�����Խ��\n");
    // ��־���Ѿ����
    m_isSolvePEB = true;
    return;
}

#define DLLPATH L"..\\HookAPI\\Dll4HookAPI.dll"
void CDebugger::DebugHookAPI(HANDLE process)
{
    // 2.��Ŀ�����������ռ�
    LPVOID lpPathAddr = VirtualAllocEx(
        process,			        // Ŀ����̾��
        0,							// ָ�������ַ
        wcslen(DLLPATH) * 2 + 2,	// ����ռ��С
        MEM_RESERVE | MEM_COMMIT,	// �ڴ��״̬
        PAGE_READWRITE);			// �ڴ�����

    // 3.��Ŀ�������д��Dll·��
    DWORD dwWriteSize = 0;
    WriteProcessMemory(
        process,				    // Ŀ����̾��
        lpPathAddr,					// Ŀ����̵�ַ
        DLLPATH,					// д��Ļ�����
        wcslen(DLLPATH) * 2 + 2,	// ��������С
        &dwWriteSize);				// ʵ��д���С

    // 4.��Ŀ������д����߳�
    HANDLE hThread = CreateRemoteThread(
        process,					// Ŀ����̾��
        NULL,						// ��ȫ����
        NULL,						// ջ��С
        (PTHREAD_START_ROUTINE)LoadLibraryW,	// �ص�����
        lpPathAddr,					// �ص���������
        NULL,						// ��־
        NULL						// �߳�ID
    );

    // 5.�ȴ��߳̽���
    //WaitForSingleObject(hThread, -1);

    // 6.������
    //VirtualFreeEx(process, lpPathAddr, 0, MEM_RELEASE);
    //CloseHandle(hThread);
    //CloseHandle(process);

    printf("DebugPort�����Խ��\n");
    return;
}

CString GetRoute(CString type, CString nFileName)
{

    TCHAR szFileName[MAX_PATH] = { 0 };
    _tcscpy_s(szFileName, MAX_PATH, nFileName);


    OPENFILENAME openFileName = { 0 };
    openFileName.lStructSize = sizeof(OPENFILENAME);
    //���ļ��Ի���
    openFileName.nMaxFile = MAX_PATH;
    openFileName.lpstrFile = szFileName;
    openFileName.nFilterIndex = 1;
    openFileName.Flags = OFN_PATHMUSTEXIST | OFN_FILEMUSTEXIST | OFN_NOCHANGEDIR;
    openFileName.lpstrFilter = L"��ִ���ļ�(*.exe)\0*.exe\0";

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

    DWORD nPeSize = 0;				//PEͷ
    DWORD nImageSize = 0;			//�ڴ��д�С
    DWORD nFileSize = 0;			//�ļ���С
    DWORD nSectionNum = 0;			//��������
    PBYTE nPeHeadData = nullptr;	//PE����
    PBYTE nImageBuf = nullptr;		//�ļ�����
    FILE* pFile = nullptr;			//д���ļ�ָ��
    CString nFilePath;				//�����ļ�·��

    nPeHeadData = new BYTE[4096]{};

    //��ȡ�ļ�ͷ��Ϣ
    ReadMemoryBytes(nImageBassAddress, nPeHeadData, 4096);

    //��ȡPE��Ϣ
    PIMAGE_DOS_HEADER nDosHead = (PIMAGE_DOS_HEADER)nPeHeadData;
    PIMAGE_NT_HEADERS nNtHead = (PIMAGE_NT_HEADERS)(nPeHeadData + nDosHead->e_lfanew);
    PIMAGE_SECTION_HEADER nSecetionHead = IMAGE_FIRST_SECTION(nNtHead);

    //PEͷ��С
    nPeSize = nNtHead->OptionalHeader.SizeOfHeaders;
    //�ļ��ĳߴ�
    nImageSize = nNtHead->OptionalHeader.SizeOfImage;
    //��������	
    nSectionNum = nNtHead->FileHeader.NumberOfSections;


    //����exe����Ķѿռ�
    nImageBuf = new BYTE[nImageSize]{};

    //��ȡPE����
    ReadMemoryBytes(nImageBassAddress, nImageBuf, nPeSize);

    nFileSize += nPeSize;
    //��ȡÿ�����ε�����
    for (DWORD i = 0; i < nSectionNum; i++)
    {
        ReadMemoryBytes(nImageBassAddress + nSecetionHead[i].VirtualAddress, nImageBuf + nSecetionHead[i].PointerToRawData, nSecetionHead[i].SizeOfRawData);
        nFileSize += nSecetionHead[i].SizeOfRawData;
    }

    //�޸��ļ�����
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

    printf("�����ļ��� %s �ɹ�\n",nFilePath);
}

BOOL CDebugger::LoadSymbol(CREATE_PROCESS_DEBUG_INFO* pInfo) 
{

    //�򿪽��̻�ý��̾��
    m_SymHandle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, m_processInfo.dwProcessId);

    //��ʼ�����Ŵ�����
    SymInitialize(m_SymHandle, NULL, FALSE);

    //��������ļ�
    SymLoadModule64(m_SymHandle, pInfo->hFile, NULL, NULL, (DWORD64)pInfo->lpBaseOfImage, 0);

    IMAGEHLP_MODULE64 nIMAGEHLP_MODULE64{};
    nIMAGEHLP_MODULE64.SizeOfStruct = sizeof(IMAGEHLP_MODULE64);
    SymGetModuleInfo64(m_SymHandle, (DWORD64)pInfo->lpBaseOfImage, &nIMAGEHLP_MODULE64);

    return TRUE;
}