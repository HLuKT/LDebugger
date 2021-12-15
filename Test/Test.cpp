#include <Windows.h>
#include <stdio.h>
#include <winternl.h>
#pragma comment(lib,"ntdll.lib")

int g_num1 = 1;
int g_num2 = 2;


int g_num3 = 100;
int g_num4 = 200;

void fun()
{
	int a = 100 + 100;
	return;
}

int main()
{
	_asm mov eax, 100; //  00411908
					   // 查看、修改反汇编
					   // 打印栈
					   // 查看内存数据 全局变量  g_num1
					   // 修改寄存器
					   // 查看进程模块
					   // 单步不步过-步入
	fun();			   // 0041190D

	// 循环，测试软件永久断点
	for (int i = 0; i < 3; i++)
	{
		printf("测试软件永久断点[%d] \n", i);   // 004118FB
		Sleep(300);
	}

	// 循环，测试硬件永久断点 -执行
	for (int i = 0; i < 3; i++)
	{
		printf("测试硬件永久断点-执行[%d] \n", i);  //  0041193A
		Sleep(300);
	}
	// 设置硬件写入断点
	g_num1 = g_num1 + 1;  //  00411962

	_asm nop;

	// 硬件的访问断点-读写
	g_num2 = g_num2 + 3;       // 00411970

	// 循环，测试内存执行断点
	//for (int i = 0; i < 3; i++)
	//{
	//	printf("测试内存执行断点[%d] \n", i);  // 004119CC
	//	Sleep(300);
	//}
	char szString[20] = { "HelloWorld!" }; //00417B54
	while (1)
	{
		printf("%s\n", szString);
		Sleep(2000);
	}

	// 设置内存写入断点 
	g_num3 = g_num3 + 1;   //004119BC

	_asm nop;

	// 内存读写断点
	g_num4 += g_num4 + 3;        //004119D0

	// 循环 条件断点 eax=2
	for (int i = 0; i < 3; i++) //004119F6
	{
		printf("循环 条件断点 eax=2 [%d] \n", i);
		Sleep(300);
	}



	// 反调试
	if (IsDebuggerPresent())
	{
		printf("BeingDebugged:有调试器\n");
	}
	else {
		printf("BeingDebugged:没有调试器\n");
	}

	int nDebugPort = 0;
	NtQueryInformationProcess(
		GetCurrentProcess(), 	    // 目标进程句柄
		ProcessDebugPort, 	        // 查询信息类型
		&nDebugPort, 		        // 输出查询信息
		sizeof(nDebugPort), 	    // 查询类型大小
		NULL); 			            // 实际返回数据大小
	if (nDebugPort == -1)
	{
		printf("ProcessDebugPort:有调试器\n");
	}
	else {
		printf("ProcessDebugPort:没有调试器\n");

	}
	system("pause");
}

//#include <iostream>
//#include <Windows.h>
//int a;
//int main()
//{
//    //char hello  [10] = { "helloword" };
//    //41195B
//    while (true)
//    {
//        char hello[10] = { "helloword" };
//        a += 1;
//        printf("%d", a);
//        printf("%s\n", hello);
//        Sleep(1000);
//    }
//    return 0;
//}