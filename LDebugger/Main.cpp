#include <iostream>
#include "CDebugger.h"
#include "Plugin.h"
CDebugger debug;

int main()
{
	while (TRUE)
	{
		printf("[1.]	�������Խ���\n");
		printf("[2.]	���ӵ��Խ���\n");
		int input = 0;
		scanf_s("%d", &input);
		if (input == 1)
		{			

			// 1.��������
			printf("��������Խ��̵�·��:\n");
			char Path[MAX_PATH] = { 0 };
			scanf_s("%s", Path, MAX_PATH);
			// ���ز��
			Plugin::LoadPlugin();
			debug.StartDebug(Path);
			debug.DispatchEvent();
			// ж�ز��
			Plugin::ReleasePlg();				
			break;
		}
		else if (input == 2)
		{
			// 2.���ӽ���
			printf("�����븽�ӽ��̵�PID\n");
			DWORD dwPid = 0;
			scanf_s("%d", &dwPid);
			debug.AttachDebug(dwPid);
			debug.DispatchEvent();
			break;
		}
		else
		{
			printf("����������\n");
		}
	}
}




