#pragma once
#include <windows.h>
#include "keystone/include/keystone.h"// ����ͷ�ļ�
#pragma comment (lib,"keystone/lib/keystone_x86.lib")// ������̬��

class Keystone
{
public:
	static void printOpcode(const unsigned char* pOpcode, int nSize);// ��ӡopcode
	static int Asm(HANDLE process_handle, LPVOID Addr, char asmCode[]);
};