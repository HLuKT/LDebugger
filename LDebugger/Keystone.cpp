#include "Keystone.h"
#include <string>

// ��ӡopcode
void Keystone::printOpcode(const unsigned char* pOpcode, int nSize)
{
	for (int i = 0; i < nSize; ++i)
	{
		printf("%02X", pOpcode[i]);
	}
}



int Keystone::Asm(HANDLE process_handle, LPVOID Addr, char asmCode[])
{
	ks_engine *pengine = NULL;
	if (KS_ERR_OK != ks_open(KS_ARCH_X86, KS_MODE_32, &pengine))
	{
		printf("����������ʼ��ʧ��\n");
		return 0;
	}
	unsigned char* opcode = NULL; // ���õ���opcode�Ļ������׵�ַ
	unsigned int nOpcodeSize = 0; // ��������opcode���ֽ���

	// ���ָ��
	// ����ʹ�÷ֺţ����߻��з���ָ��ָ���
	//char asmCode[] =
	//{
	//	"mov eax,ebx;mov eax,1;mov dword ptr ds:[eax],20"
	//};

	int nRet = 0; // ���溯���ķ���ֵ�������жϺ����Ƿ�ִ�гɹ�
	size_t stat_count = 0; // ����ɹ�����ָ�������

	nRet = ks_asm(pengine, /* �����������ͨ��ks_open�����õ�*/
		asmCode, /*Ҫת���Ļ��ָ��*/
		(uint64_t)Addr, /*���ָ�����ڵĵ�ַ*/
		&opcode,/*�����opcode*/
		&nOpcodeSize,/*�����opcode���ֽ���*/
		&stat_count /*����ɹ�����ָ�������*/
	);

	// ����ֵ����-1ʱ��������
	if (nRet == -1)
	{
		// ���������Ϣ
		// ks_errno ��ô�����
		// ks_strerror ��������ת�����ַ���������������ַ���
		printf("������Ϣ��%s\n", ks_strerror(ks_errno(pengine)));
		return 0;
	}
	//printf("һ��ת���� %d ��ָ��\n", stat_count);
	//printOpcode(opcode, nOpcodeSize);// ��ӡ��������opcode
	
	// д���ڴ�
	WriteProcessMemory(process_handle, Addr, opcode, nOpcodeSize, NULL);
	
	ks_free(opcode);// �ͷſռ�
	ks_close(pengine);// �رվ��
	return nOpcodeSize;
}

