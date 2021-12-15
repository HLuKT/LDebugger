#include "CBreakPoint.h"
#include "CDebugger.h"
BOOL int3on = TRUE;
//int3����ϵ��б�
vector<BREAKPOINTINFO> CBreakPoint::vec_BreakPointList;
//�ڴ�ϵ�
vector<MEMBREAKPOINTINFO> CBreakPoint::vec_MemoryBreakPointList;

/*
    ���Դ������̣�
    TF��1 -> ִ�д��� -> CPU�����ж� -> IDT���������� -> ����ϵͳ�����쳣�ַ� ->
    ��������ϵͳ���͵����¼� -> �������õ�EXCEPTION_DEBUG_EVENT�쳣�¼� -> ��������ʾ�������Ϣ
*/
//TF:���Ա�־λ����TF=1ʱ��������ÿ��ִֻ��һ��ָ�������ִ��
/*ʵ�ֵ����ϵ�*/
//���õ�������ϵ㡪��TF�ϵ�
void CBreakPoint::setBreakpoint_tf(HANDLE thread)
{
    //1.��ȡ�̻߳����������ģ����а���EFLAGS�Ĵ���
    CONTEXT context = { 0 };
    context.ContextFlags = CONTEXT_ALL;
    GetThreadContext(thread, &context);

    //2.��TF��־λ����1
    context.EFlags |= 0x100;

    //3.�����̻߳�����
    SetThreadContext(thread, &context);
}
//���õ��������ϵ�
void CBreakPoint::setBreakpoint_tf_int3(HANDLE process, HANDLE thread)
{
    //1.��ȡ��ǰEIP
    CONTEXT context = { 0 };
    context.ContextFlags = CONTEXT_ALL;
    GetThreadContext(thread, &context);
    DWORD CallAddr = context.Eip;
    //2.��ȡcallָ���
    // �鿴EIPλ�õķ�������
    int CallLen = Capstone::GetCallCodeLen(process, LPVOID(CallAddr));
    //3.�ж��Ƿ���call�����򲽹�
    if (CallLen != -1)
    {
        //4.��ǰ��ַ+����=��һ��ָ���ַ���漴��int3�ϵ�
        LPVOID addr = LPVOID(CallAddr + CallLen);
        CBreakPoint::setBreakpoint_int3(process, addr);
        //// 1.��������ϵ���Ϣ�Ľṹ��
        //BREAKPOINTINFO info = { addr };
        //DWORD INS = 0;
        //// 2.��ȡĿ���ַԭ�е�OPCODE�����ڻָ�ִ��
        //ReadProcessMemory(process, addr, &info.oldOpcode, 1, &INS);
        //// 3.��Ŀ����̵ĵ�ַд�� \xcc �ֽ�
        //WriteProcessMemory(process, addr, "\xCC", 1, &INS);
        int3on = FALSE;
    }
    //5.����call����������������
    else
    {
        CBreakPoint::setBreakpoint_tf(thread);
        int3on = TRUE;
    }
}

/*ʵ������ϵ�*/
//��������ϵ�
void CBreakPoint::setBreakpoint_int3(HANDLE process, LPVOID addr,BOOL res)
{
    // 1.��������ϵ���Ϣ�Ľṹ��
    BREAKPOINTINFO info = { addr };
    info.m_bReset = res;
    DWORD INS = 0;
    // 2.��ȡĿ���ַԭ�е�OPCODE�����ڻָ�ִ��
    ReadProcessMemory(process, addr, &info.oldOpcode, 1, &INS);
    // 3.��Ŀ����̵ĵ�ַд�� \xcc �ֽ�
    WriteProcessMemory(process, addr, "\xCC", 1, &INS);
    // 4.�����õĶϵ���ӵ�������
    vec_BreakPointList.push_back(info);
}

//��������ϵ�
BOOL CBreakPoint::Setint3ForeverBreakPoint(HANDLE process)
{
    for (int i = 0; i < vec_BreakPointList.size(); i++)
    {
        if (TRUE == vec_BreakPointList[i].m_bReset)
        {
            BYTE oldBytes;
            DWORD dwRead = 0;
            ReadProcessMemory(process, vec_BreakPointList[i].addr, &oldBytes, 1, &dwRead);
            //��Ϊ���öϵ�ʱ��ȡ��ǰλ�ò鿴�Ƿ���CC�����CC������
            if (oldBytes != 204)
            {
                ReadProcessMemory(process, vec_BreakPointList[i].addr, &vec_BreakPointList[i].oldOpcode, 1, &dwRead);
                WriteProcessMemory(process, vec_BreakPointList[i].addr, "\xcc", 1, &dwRead);
                int3on = FALSE;
            }
        }
    }
    return TRUE;
}

//�Ƴ�����ϵ�
void CBreakPoint::removeBreakpoint_int3(HANDLE process, HANDLE thread, LPVOID addr)
{
    // ԭ��һ������ϵ���£����������������쳣�����Ե�ǰEipָ�����
    // �����쳣����һ��ָ�Ȼ������Ϊ���ó��������������У�������Ҫ��
    // EIPָ�����cc�ĵط������ҽ�ԭ�е�����д��ȥ
    DWORD INS = 0;
    // 1.�����ϵ��б��ҵ���Ҫ�޸��Ķϵ�
    for (int i = 0; i < vec_BreakPointList.size(); ++i)
    {
        // 2.��ַ��ͬ���޸�����������
        if (vec_BreakPointList[i].addr == addr)
        {
            // 3.��ȡ�̻߳�����
            CONTEXT context = { 0 };
            context.ContextFlags = CONTEXT_CONTROL;
            GetThreadContext(thread, &context);
            // 4.��Ϊ���������쳣����eip - 1
            context.Eip -= 1;
            SetThreadContext(thread, &context);
            // 5.��ԭ�е�����д��ָ����λ��
            WriteProcessMemory(process, addr, &vec_BreakPointList[i].oldOpcode, 1, &INS);
            // 6.���öϵ�(��־λ����) / ��ͨ�ϵ�(ֱ��ɾ��)
            //vec_BreakPointList.erase(vec_BreakPointList.begin() + i);
        }
    }
}

/*ʵ��Ӳ���ϵ�*/
//����Ӳ��ִ�жϵ�
void CBreakPoint::setBreakpoint_hardExec(HANDLE thread, DWORD addr)
{
    // ԭ����CPU�ṩ��Drϵ�мĴ��������������4��Ӳ���ϵ㣬�ϵ��
    // λ����Dr0~Dr3ȥ���棬��Ӧ��Dr7�е�Ln��ʾ��Ӧ�Ķϵ��Ƿ���Ч,
    // Dr7�Ĵ������ṩ��RW\LEN��־λ,�������öϵ�����͡�
    // RW:0(ִ�жϵ�,����lenҲ����Ϊ0���� 1(д) 3(��д��
    // len:0(1�ֽ�), 1��2�ֽ�), 2��8�ֽ�), 3��4�ֽ�)
    
    // 1.��ȡ�̻߳�����
    CONTEXT context = { 0 };
    context.ContextFlags = CONTEXT_DEBUG_REGISTERS;
    GetThreadContext(thread, &context);
    // 2.��ȡ�� Dr7 �Ĵ���,���б�������Щ�ϵ㱻ʹ��
    PDBG_REG7 Dr7 = (PDBG_REG7)&context.Dr7;
    // 3.�ж��Ƿ����ã�û�����þ�����
    if (Dr7->L0 == 0)           //Dr0û�б�ʹ��
    {
        context.Dr0 = addr;	    // ���õ�ַ
        Dr7->RW0 = 0;			// �������ͣ�0��ִ�У�1��д��3����д��
        Dr7->LEN0 = 0;			// ����������Ϊ0
        Dr7->L0 = 1;		    // ������һ���ϵ�
    }
    else if (Dr7->L1 == 0)      //Dr1û�б�ʹ��
    {
        context.Dr1 = addr;     // ���õ�ַ
        Dr7->RW1 = 0;           // �������ͣ�0��ִ�У�1��д��3����д��
        Dr7->LEN1 = 0;          // ����������Ϊ0
        Dr7->L1 = 1;            // �����ڶ����ϵ�
    }
    else if (Dr7->L2 == 0)      //Dr2û�б�ʹ��
    {
        context.Dr2 = addr;     // ���õ�ַ
        Dr7->RW2 = 0;           // �������ͣ�0��ִ�У�1��д��3����д��
        Dr7->LEN2 = 0;          // ����������Ϊ0
        Dr7->L2 = 1;            // �����������ϵ�
    }
    else if (Dr7->L3 == 0)      //Dr3û�б�ʹ��
    {
        context.Dr3 = addr;     // ���õ�ַ
        Dr7->RW3 = 0;           // �������ͣ�0��ִ�У�1��д��3����д��
        Dr7->LEN3 = 0;          // ����������Ϊ0
        Dr7->L3 = 1;            // �������ĸ��ϵ�
    }
    else
    {
        printf("Ӳ���ϵ�ֻ������4��!\n");
    }
    // 4.д���޸ĵļĴ�������
    SetThreadContext(thread, &context);
}

//����Ӳ����д�ϵ�
void CBreakPoint::setBreakpoint_hardRW(HANDLE thread, DWORD addr, DWORD dwLen)
{
    // ԭ����CPU�ṩ��Drϵ�мĴ��������������4��Ӳ���ϵ㣬�ϵ��
    // λ����Dr0~Dr3ȥ���棬��Ӧ��Dr7�е�Ln��ʾ��Ӧ�Ķϵ��Ƿ���Ч,
    // Dr7�Ĵ������ṩ��RW\LEN��־λ,�������öϵ�����͡�
    // RW:0(ִ�жϵ�,����lenҲ����Ϊ0���� 1(д) 3(��д��
    // len:0(1�ֽ�), 1��2�ֽ�), 2��8�ֽ�), 3��4�ֽ�)

    // 1.��ȡ�̻߳�����
    CONTEXT context = { 0 };
    context.ContextFlags = CONTEXT_DEBUG_REGISTERS;
    GetThreadContext(thread, &context);
    // 2.��ȡ�� Dr7 �Ĵ���,���б�������Щ�ϵ㱻ʹ��
    PDBG_REG7 Dr7 = (PDBG_REG7)&context.Dr7;
    // 3 �Ե�ַ�ͳ��Ƚ��ж��봦��
    if (dwLen == 1) {           //2�ֽڵĶ�������
        addr = addr - addr % 2;
    }     
    else if (dwLen == 3){       //4�ֽڵĶ�������
        addr = addr - addr % 4;
    }    
    else if (dwLen > 3) {
        return;
    }     
    // 4.�ж��Ƿ����ã�û�����þ�����
    if (Dr7->L0 == 0)           //Dr0û�б�ʹ��
    {
        context.Dr0 = addr;		// ���õ�ַ
        Dr7->RW0 = 3;			// �������ͣ�0��ִ�У�1��д��3����д��
        Dr7->LEN0 = dwLen;		// ����������Ϊ0
        Dr7->L0 = 1;			// �������ĸ��ϵ�
    }
    else if (Dr7->L1 == 0)      //Dr1û�б�ʹ��
    {
        context.Dr1 = addr;     // ���õ�ַ
        Dr7->RW1 = 3;           // �������ͣ�0��ִ�У�1��д��3����д��
        Dr7->LEN1 = dwLen;      // ����������Ϊ0
        Dr7->L1 = 1;            // �������ĸ��ϵ�
    }
    else if (Dr7->L2 == 0)      //Dr2û�б�ʹ��
    {
        context.Dr2 = addr;     // ���õ�ַ
        Dr7->RW2 = 3;           // �������ͣ�0��ִ�У�1��д��3����д��
        Dr7->LEN2 = dwLen;      // ����������Ϊ0
        Dr7->L2 = 1;            // �������ĸ��ϵ�
    }
    else if (Dr7->L3 == 0)      //Dr3û�б�ʹ��
    {
        context.Dr3 = addr;     // ���õ�ַ
        Dr7->RW3 = 3;           // �������ͣ�0��ִ�У�1��д��3����д��
        Dr7->LEN3 = dwLen;      // ����������Ϊ0
        Dr7->L3 = 1;            // �������ĸ��ϵ�
    }
    else
    {
        printf("Ӳ���ϵ�ֻ������4��!\n");
    }
    // 5.д���޸ĵļĴ�������
    SetThreadContext(thread, &context);
}

//�Ƴ�Ӳ���ϵ�
void CBreakPoint::removeBreakpoint_hard(HANDLE thread)
{
    //ԭ�������Ӳ���ϵ�������ˣ��ڴ���ʱ�����ԼĴ���
    //Dr6�ĵ�4λ����Ӧ�ı�־λ�ͻ���Ϊ1
    //��0λ��1�ʹ���Dr0�еĶϵ�������ˣ�Ȼ�����������

    // 1.��ȡ�̻߳�����
    CONTEXT context = { 0 };
    context.ContextFlags = CONTEXT_DEBUG_REGISTERS;
    GetThreadContext(thread, &context);
    // 2.��ȡ�� Dr7 �Ĵ���,���б�������Щ�ϵ㱻ʹ��
    PDBG_REG7 Dr7 = (PDBG_REG7)&context.Dr7;
    // 3.�ж�����һ���ϵ㴥���ˣ������
    switch (context.Dr6 & 0xF)
    {
    case 1:
        Dr7->L0 = 0;  break;
    case 2:
        Dr7->L1 = 0;  break;
    case 4:
        Dr7->L2 = 0;  break;
    case 8:
        Dr7->L3 = 0;  break;
    }    
    // 4.�������üĴ�����Ϣ
    SetThreadContext(thread, &context);

}

/*ʵ���ڴ�ϵ�*/
//�����ڴ�ִ�жϵ�
void CBreakPoint::setBreakpoint_memoryExec(HANDLE process, HANDLE thread, LPVOID addr, BOOL res)
{
    // 1.���ø��ڴ�ҳΪ���ɷ���
    DWORD dwTempProtect;
    MEMBREAKPOINTINFO info = { addr };
    info.m_bReset = res;
    VirtualProtectEx(process, addr, 1, PAGE_READWRITE, &dwTempProtect);
    // 2.�����ַ���Ա�,�ָ�ԭ����
    info.addr = addr;
    info.oldAttribute = dwTempProtect;
    vec_MemoryBreakPointList.push_back(info);
}
//�����ڴ��д�ϵ�
void CBreakPoint::setBreakpoint_memoryRW(HANDLE process, HANDLE thread, LPVOID addr, BOOL res)
{
    // 1.���ø��ڴ�ҳΪ���ɷ���
    DWORD dwTempProtect;
    MEMBREAKPOINTINFO info = { addr };
    info.m_bReset = res;
    VirtualProtectEx(process, addr, 1, PAGE_NOACCESS, &dwTempProtect);
    // 2.�����ַ���Ա�,�ָ�ԭ����
    info.addr = addr;
    info.oldAttribute = dwTempProtect;
    vec_MemoryBreakPointList.push_back(info);
}

//�����ڴ�ϵ�
BOOL CBreakPoint::SetmemoryForeverBreakPoint(HANDLE process, LPVOID addr)
{
    //����ҳ�ڴ����ԣ�����ԭʼ����
    DWORD ns = 0;
    for (int i = 0; i < vec_MemoryBreakPointList.size(); i++)
    {
        VirtualProtectEx(process, vec_MemoryBreakPointList[i].addr, 1, PAGE_NOACCESS, &ns);
        int3on = FALSE;
    }
    return TRUE;
}

//�Ƴ��ڴ�ϵ�
bool CBreakPoint::removeBreakpoint_memory(HANDLE process, HANDLE thread, LPVOID addr)
{
    bool isFind = FALSE;
    // 1.�����ϵ��б��ҵ���Ҫ�޸��Ķϵ�
    for (int i = 0; i < vec_MemoryBreakPointList.size(); ++i)
    {
        // 1.���˵�ַ���ǵ������õĵ�ַ
        if (addr != vec_MemoryBreakPointList[i].addr)
        {
            // �ٻָ�Ϊԭ����
            DWORD dwTempProtect;
            VirtualProtectEx(process, addr, 1, vec_MemoryBreakPointList[i].oldAttribute, &dwTempProtect);
            // ������һ��tf�����ϵ�
            setBreakpoint_tf(thread);
            isFind = FALSE;
        }
    // 2.���˵�ַ�ǵ������õĵ�ַ
        else
        {
            DWORD dwTempProtect;
            // �ָ�Ϊԭ����
            VirtualProtectEx(process, addr, 1, vec_MemoryBreakPointList[i].oldAttribute, &dwTempProtect);
            // ������һ��TF�����ϵ�
            //setBreakpoint_tf(thread);
            isFind = TRUE;
        }
    }
    return isFind;
}

/*ʵ�������ϵ�*/
//���������ϵ�
void CBreakPoint::setBreakpoint_condition(HANDLE process, HANDLE thread, LPVOID addr, int eax)
{
    setBreakpoint_int3(process, addr);
}

//�Ƴ������ϵ�
bool CBreakPoint::removeBreakpoint_condition(HANDLE process, HANDLE thread, LPVOID addr, int eax)
{
    bool isFind = false;
    // 1.��ȡ�̻߳�����
    CONTEXT context = { 0 };
    context.ContextFlags = CONTEXT_ALL;
    GetThreadContext(thread, &context);
    if (context.Eax != eax)
    {
        CBreakPoint::removeBreakpoint_int3(process, thread, addr);
        setBreakpoint_tf(thread);
        isFind = false;
    }
    else
    {
        CBreakPoint::removeBreakpoint_int3(process, thread, addr);
        isFind = true;
    }
    return isFind;
}
//API�ϵ�
//SIZE_T FindApiAddress(HANDLE hProcess, const char* pszName)
//{
//    char buffer[sizeof(SYMBOL_INFO) + MAX_SYM_NAME * sizeof(TCHAR)];
//    PSYMBOL_INFO pSymbol = (PSYMBOL_INFO)buffer;
//    pSymbol->SizeOfStruct = sizeof(SYMBOL_INFO);
//    pSymbol->MaxNameLen = MAX_SYM_NAME;
//    //�������ֲ�ѯ������Ϣ�������pSymbol��
//    if (!SymFormName(hProcess,pszName,pSymbol)
//    {
//        return 0;
//    }
//    //���غ�����ַ
//    return (SIZE_T)pSymbol->Address;
//}

void CBreakPoint::setBreakpoint_API(HANDLE process, const char* pszApiName)
{
    // ����API�ĵ�ַ
    unsigned int address = DbgSymbol::FindApiAddress(process, pszApiName);
    if (address == 0)
    { 
        return;
    }
    else
    {
        // ���һ������ϵ�
        setBreakpoint_int3(process, (LPVOID)address);
    }  
}
