#include "CBreakPoint.h"
#include "CDebugger.h"
BOOL int3on = TRUE;
//int3软件断点列表
vector<BREAKPOINTINFO> CBreakPoint::vec_BreakPointList;
//内存断点
vector<MEMBREAKPOINTINFO> CBreakPoint::vec_MemoryBreakPointList;

/*
    调试处理流程：
    TF置1 -> 执行代码 -> CPU产生中断 -> IDT函数被调用 -> 操作系统进行异常分发 ->
    调试器子系统发送调试事件 -> 调试器得到EXCEPTION_DEBUG_EVENT异常事件 -> 调试器显示反汇编信息
*/
//TF:调试标志位。当TF=1时，处理器每次只执行一条指令，即单步执行
/*实现单步断点*/
//设置单步步入断点——TF断点
void CBreakPoint::setBreakpoint_tf(HANDLE thread)
{
    //1.获取线程环境块上下文，其中包括EFLAGS寄存器
    CONTEXT context = { 0 };
    context.ContextFlags = CONTEXT_ALL;
    GetThreadContext(thread, &context);

    //2.将TF标志位置置1
    context.EFlags |= 0x100;

    //3.设置线程环境块
    SetThreadContext(thread, &context);
}
//设置单步步过断点
void CBreakPoint::setBreakpoint_tf_int3(HANDLE process, HANDLE thread)
{
    //1.获取当前EIP
    CONTEXT context = { 0 };
    context.ContextFlags = CONTEXT_ALL;
    GetThreadContext(thread, &context);
    DWORD CallAddr = context.Eip;
    //2.获取call指令长度
    // 查看EIP位置的反汇编代码
    int CallLen = Capstone::GetCallCodeLen(process, LPVOID(CallAddr));
    //3.判断是否是call，是则步过
    if (CallLen != -1)
    {
        //4.当前地址+长度=下一条指令地址，随即下int3断点
        LPVOID addr = LPVOID(CallAddr + CallLen);
        CBreakPoint::setBreakpoint_int3(process, addr);
        //// 1.创建保存断点信息的结构体
        //BREAKPOINTINFO info = { addr };
        //DWORD INS = 0;
        //// 2.读取目标地址原有的OPCODE，用于恢复执行
        //ReadProcessMemory(process, addr, &info.oldOpcode, 1, &INS);
        //// 3.向目标进程的地址写入 \xcc 字节
        //WriteProcessMemory(process, addr, "\xCC", 1, &INS);
        int3on = FALSE;
    }
    //5.不是call，则正常单步步入
    else
    {
        CBreakPoint::setBreakpoint_tf(thread);
        int3on = TRUE;
    }
}

/*实现软件断点*/
//设置软件断点
void CBreakPoint::setBreakpoint_int3(HANDLE process, LPVOID addr,BOOL res)
{
    // 1.创建保存断点信息的结构体
    BREAKPOINTINFO info = { addr };
    info.m_bReset = res;
    DWORD INS = 0;
    // 2.读取目标地址原有的OPCODE，用于恢复执行
    ReadProcessMemory(process, addr, &info.oldOpcode, 1, &INS);
    // 3.向目标进程的地址写入 \xcc 字节
    WriteProcessMemory(process, addr, "\xCC", 1, &INS);
    // 4.将设置的断点添加到链表中
    vec_BreakPointList.push_back(info);
}

//永久软件断点
BOOL CBreakPoint::Setint3ForeverBreakPoint(HANDLE process)
{
    for (int i = 0; i < vec_BreakPointList.size(); i++)
    {
        if (TRUE == vec_BreakPointList[i].m_bReset)
        {
            BYTE oldBytes;
            DWORD dwRead = 0;
            ReadProcessMemory(process, vec_BreakPointList[i].addr, &oldBytes, 1, &dwRead);
            //当为永久断点时获取当前位置查看是否是CC如果是CC不重设
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

//移除软件断点
void CBreakPoint::removeBreakpoint_int3(HANDLE process, HANDLE thread, LPVOID addr)
{
    // 原理：一但软件断点断下，由于他是陷阱类异常，所以当前Eip指向的是
    // 产生异常的吓一跳指令，然后我们为了让程序能正常的运行，我们需要将
    // EIP指向产生cc的地方，并且将原有的数据写回去
    DWORD INS = 0;
    // 1.遍历断点列表，找到需要修复的断点
    for (int i = 0; i < vec_BreakPointList.size(); ++i)
    {
        // 2.地址相同才修复，否则会出错
        if (vec_BreakPointList[i].addr == addr)
        {
            // 3.获取线程环境块
            CONTEXT context = { 0 };
            context.ContextFlags = CONTEXT_CONTROL;
            GetThreadContext(thread, &context);
            // 4.因为是陷阱类异常，故eip - 1
            context.Eip -= 1;
            SetThreadContext(thread, &context);
            // 5.将原有的数据写回指定的位置
            WriteProcessMemory(process, addr, &vec_BreakPointList[i].oldOpcode, 1, &INS);
            // 6.永久断点(标志位设置) / 普通断点(直接删掉)
            //vec_BreakPointList.erase(vec_BreakPointList.begin() + i);
        }
    }
}

/*实现硬件断点*/
//设置硬件执行断点
void CBreakPoint::setBreakpoint_hardExec(HANDLE thread, DWORD addr)
{
    // 原理：由CPU提供的Dr系列寄存器做多可以设置4个硬件断点，断点的
    // 位置由Dr0~Dr3去保存，相应的Dr7中的Ln表示对应的断点是否有效,
    // Dr7寄存器还提供了RW\LEN标志位,用于设置断点的类型。
    // RW:0(执行断点,它的len也必须为0）， 1(写) 3(读写）
    // len:0(1字节), 1（2字节), 2（8字节), 3（4字节)
    
    // 1.获取线程环境块
    CONTEXT context = { 0 };
    context.ContextFlags = CONTEXT_DEBUG_REGISTERS;
    GetThreadContext(thread, &context);
    // 2.获取到 Dr7 寄存器,其中保存了哪些断点被使用
    PDBG_REG7 Dr7 = (PDBG_REG7)&context.Dr7;
    // 3.判断是否启用，没有启用就设置
    if (Dr7->L0 == 0)           //Dr0没有被使用
    {
        context.Dr0 = addr;	    // 设置地址
        Dr7->RW0 = 0;			// 设置类型（0：执行，1：写，3：读写）
        Dr7->LEN0 = 0;			// 长度域设置为0
        Dr7->L0 = 1;		    // 开启第一个断点
    }
    else if (Dr7->L1 == 0)      //Dr1没有被使用
    {
        context.Dr1 = addr;     // 设置地址
        Dr7->RW1 = 0;           // 设置类型（0：执行，1：写，3：读写）
        Dr7->LEN1 = 0;          // 长度域设置为0
        Dr7->L1 = 1;            // 开启第二个断点
    }
    else if (Dr7->L2 == 0)      //Dr2没有被使用
    {
        context.Dr2 = addr;     // 设置地址
        Dr7->RW2 = 0;           // 设置类型（0：执行，1：写，3：读写）
        Dr7->LEN2 = 0;          // 长度域设置为0
        Dr7->L2 = 1;            // 开启第三个断点
    }
    else if (Dr7->L3 == 0)      //Dr3没有被使用
    {
        context.Dr3 = addr;     // 设置地址
        Dr7->RW3 = 0;           // 设置类型（0：执行，1：写，3：读写）
        Dr7->LEN3 = 0;          // 长度域设置为0
        Dr7->L3 = 1;            // 开启第四个断点
    }
    else
    {
        printf("硬件断点只能设置4个!\n");
    }
    // 4.写入修改的寄存器环境
    SetThreadContext(thread, &context);
}

//设置硬件读写断点
void CBreakPoint::setBreakpoint_hardRW(HANDLE thread, DWORD addr, DWORD dwLen)
{
    // 原理：由CPU提供的Dr系列寄存器做多可以设置4个硬件断点，断点的
    // 位置由Dr0~Dr3去保存，相应的Dr7中的Ln表示对应的断点是否有效,
    // Dr7寄存器还提供了RW\LEN标志位,用于设置断点的类型。
    // RW:0(执行断点,它的len也必须为0）， 1(写) 3(读写）
    // len:0(1字节), 1（2字节), 2（8字节), 3（4字节)

    // 1.获取线程环境块
    CONTEXT context = { 0 };
    context.ContextFlags = CONTEXT_DEBUG_REGISTERS;
    GetThreadContext(thread, &context);
    // 2.获取到 Dr7 寄存器,其中保存了哪些断点被使用
    PDBG_REG7 Dr7 = (PDBG_REG7)&context.Dr7;
    // 3 对地址和长度进行对齐处理
    if (dwLen == 1) {           //2字节的对齐粒度
        addr = addr - addr % 2;
    }     
    else if (dwLen == 3){       //4字节的对齐粒度
        addr = addr - addr % 4;
    }    
    else if (dwLen > 3) {
        return;
    }     
    // 4.判断是否启用，没有启用就设置
    if (Dr7->L0 == 0)           //Dr0没有被使用
    {
        context.Dr0 = addr;		// 设置地址
        Dr7->RW0 = 3;			// 设置类型（0：执行，1：写，3：读写）
        Dr7->LEN0 = dwLen;		// 长度域设置为0
        Dr7->L0 = 1;			// 开启第四个断点
    }
    else if (Dr7->L1 == 0)      //Dr1没有被使用
    {
        context.Dr1 = addr;     // 设置地址
        Dr7->RW1 = 3;           // 设置类型（0：执行，1：写，3：读写）
        Dr7->LEN1 = dwLen;      // 长度域设置为0
        Dr7->L1 = 1;            // 开启第四个断点
    }
    else if (Dr7->L2 == 0)      //Dr2没有被使用
    {
        context.Dr2 = addr;     // 设置地址
        Dr7->RW2 = 3;           // 设置类型（0：执行，1：写，3：读写）
        Dr7->LEN2 = dwLen;      // 长度域设置为0
        Dr7->L2 = 1;            // 开启第四个断点
    }
    else if (Dr7->L3 == 0)      //Dr3没有被使用
    {
        context.Dr3 = addr;     // 设置地址
        Dr7->RW3 = 3;           // 设置类型（0：执行，1：写，3：读写）
        Dr7->LEN3 = dwLen;      // 长度域设置为0
        Dr7->L3 = 1;            // 开启第四个断点
    }
    else
    {
        printf("硬件断点只能设置4个!\n");
    }
    // 5.写入修改的寄存器环境
    SetThreadContext(thread, &context);
}

//移除硬件断点
void CBreakPoint::removeBreakpoint_hard(HANDLE thread)
{
    //原理：如果是硬件断点断下来了，在触发时，调试寄存器
    //Dr6的低4位中相应的标志位就会置为1
    //第0位置1就代表Dr0中的断点断下来了，然后依次向后推

    // 1.获取线程环境块
    CONTEXT context = { 0 };
    context.ContextFlags = CONTEXT_DEBUG_REGISTERS;
    GetThreadContext(thread, &context);
    // 2.获取到 Dr7 寄存器,其中保存了哪些断点被使用
    PDBG_REG7 Dr7 = (PDBG_REG7)&context.Dr7;
    // 3.判断是哪一个断点触发了，并解除
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
    // 4.重新设置寄存器信息
    SetThreadContext(thread, &context);

}

/*实现内存断点*/
//设置内存执行断点
void CBreakPoint::setBreakpoint_memoryExec(HANDLE process, HANDLE thread, LPVOID addr, BOOL res)
{
    // 1.设置该内存页为不可访问
    DWORD dwTempProtect;
    MEMBREAKPOINTINFO info = { addr };
    info.m_bReset = res;
    VirtualProtectEx(process, addr, 1, PAGE_READWRITE, &dwTempProtect);
    // 2.保存地址作对比,恢复原属性
    info.addr = addr;
    info.oldAttribute = dwTempProtect;
    vec_MemoryBreakPointList.push_back(info);
}
//设置内存读写断点
void CBreakPoint::setBreakpoint_memoryRW(HANDLE process, HANDLE thread, LPVOID addr, BOOL res)
{
    // 1.设置该内存页为不可访问
    DWORD dwTempProtect;
    MEMBREAKPOINTINFO info = { addr };
    info.m_bReset = res;
    VirtualProtectEx(process, addr, 1, PAGE_NOACCESS, &dwTempProtect);
    // 2.保存地址作对比,恢复原属性
    info.addr = addr;
    info.oldAttribute = dwTempProtect;
    vec_MemoryBreakPointList.push_back(info);
}

//永久内存断点
BOOL CBreakPoint::SetmemoryForeverBreakPoint(HANDLE process, LPVOID addr)
{
    //设置页内存属性，保存原始属性
    DWORD ns = 0;
    for (int i = 0; i < vec_MemoryBreakPointList.size(); i++)
    {
        VirtualProtectEx(process, vec_MemoryBreakPointList[i].addr, 1, PAGE_NOACCESS, &ns);
        int3on = FALSE;
    }
    return TRUE;
}

//移除内存断点
bool CBreakPoint::removeBreakpoint_memory(HANDLE process, HANDLE thread, LPVOID addr)
{
    bool isFind = FALSE;
    // 1.遍历断点列表，找到需要修复的断点
    for (int i = 0; i < vec_MemoryBreakPointList.size(); ++i)
    {
        // 1.若此地址不是当初设置的地址
        if (addr != vec_MemoryBreakPointList[i].addr)
        {
            // ①恢复为原属性
            DWORD dwTempProtect;
            VirtualProtectEx(process, addr, 1, vec_MemoryBreakPointList[i].oldAttribute, &dwTempProtect);
            // ②再下一个tf单步断点
            setBreakpoint_tf(thread);
            isFind = FALSE;
        }
    // 2.若此地址是当初设置的地址
        else
        {
            DWORD dwTempProtect;
            // 恢复为原属性
            VirtualProtectEx(process, addr, 1, vec_MemoryBreakPointList[i].oldAttribute, &dwTempProtect);
            // ②再下一个TF单步断点
            //setBreakpoint_tf(thread);
            isFind = TRUE;
        }
    }
    return isFind;
}

/*实现条件断点*/
//设置条件断点
void CBreakPoint::setBreakpoint_condition(HANDLE process, HANDLE thread, LPVOID addr, int eax)
{
    setBreakpoint_int3(process, addr);
}

//移除条件断点
bool CBreakPoint::removeBreakpoint_condition(HANDLE process, HANDLE thread, LPVOID addr, int eax)
{
    bool isFind = false;
    // 1.获取线程环境块
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
//API断点
//SIZE_T FindApiAddress(HANDLE hProcess, const char* pszName)
//{
//    char buffer[sizeof(SYMBOL_INFO) + MAX_SYM_NAME * sizeof(TCHAR)];
//    PSYMBOL_INFO pSymbol = (PSYMBOL_INFO)buffer;
//    pSymbol->SizeOfStruct = sizeof(SYMBOL_INFO);
//    pSymbol->MaxNameLen = MAX_SYM_NAME;
//    //根据名字查询符号信息，输出到pSymbol中
//    if (!SymFormName(hProcess,pszName,pSymbol)
//    {
//        return 0;
//    }
//    //返回函数地址
//    return (SIZE_T)pSymbol->Address;
//}

void CBreakPoint::setBreakpoint_API(HANDLE process, const char* pszApiName)
{
    // 查找API的地址
    unsigned int address = DbgSymbol::FindApiAddress(process, pszApiName);
    if (address == 0)
    { 
        return;
    }
    else
    {
        // 添加一个软件断点
        setBreakpoint_int3(process, (LPVOID)address);
    }  
}
