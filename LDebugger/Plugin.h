#pragma once
#include <iostream>
#include <windows.h>
#include <locale.h>
#include <vector>
#include <string>
using namespace std;

// ���ڱ������еĲ����Ϣ
typedef struct _PLGINFO
{
	HMODULE Base = 0;			// ���ػ�ַ
	char name[32] = { 0 };		// ���������
} PLGINFO, *PPLGINFO;
// ����ָ��
using PFUNC1 = void(*)(char*);
using PFUNC2 = void(*)();
// �����
class Plugin
{
private:
	static vector<PLGINFO> m_plugins;
public:
	// ���ز��
	static void LoadPlugin();
	// ���ò������
	static void InitAllPlugin();
	// ���ж��
	static void ReleasePlg();
};

