#include <iostream>
#include "CDebugger.h"
#include "Plugin.h"
CDebugger debug;

int main()
{
	while (TRUE)
	{
		printf("[1.]	创建调试进程\n");
		printf("[2.]	附加调试进程\n");
		int input = 0;
		scanf_s("%d", &input);
		if (input == 1)
		{			

			// 1.创建进程
			printf("请输入调试进程的路径:\n");
			char Path[MAX_PATH] = { 0 };
			scanf_s("%s", Path, MAX_PATH);
			// 加载插件
			Plugin::LoadPlugin();
			debug.StartDebug(Path);
			debug.DispatchEvent();
			// 卸载插件
			Plugin::ReleasePlg();				
			break;
		}
		else if (input == 2)
		{
			// 2.附加进程
			printf("请输入附加进程的PID\n");
			DWORD dwPid = 0;
			scanf_s("%d", &dwPid);
			debug.AttachDebug(dwPid);
			debug.DispatchEvent();
			break;
		}
		else
		{
			printf("请重新输入\n");
		}
	}
}




