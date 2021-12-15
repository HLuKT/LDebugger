#include "Plugin.h"

vector<PLGINFO> Plugin::m_plugins;

// ���ز��
void Plugin::LoadPlugin()
{
	string PluginPath = "./plugin/";
	string PFindluginPath = "./plugin/*.myplg";

	// ������������ļ���Ϣ
	WIN32_FIND_DATAA FileInfo = { 0 };

	// ���������·�����������ú�׺��
	HANDLE FindHandle = FindFirstFileA(PFindluginPath.c_str(), &FileInfo);

	// һ��һ������
	do {

		string FilePath = PluginPath + FileInfo.cFileName;
		// ���� DLL �ļ������ұ��浽һ������
		HMODULE Handle = LoadLibraryA(FilePath.c_str());

		// ���ģ����سɹ�����Ҫ����ṩ�Լ�����Ϣ����ʽ���ǵ���һ���ض��ĺ���
		if (Handle)
		{
			PLGINFO info = { Handle };
			PFUNC1 func = (PFUNC1)GetProcAddress(Handle, "init");

			// ���������ȡ�ɹ�
			if (func)
			{
				func(info.name);
				m_plugins.push_back(info);
				printf("�����Ϣ: %s �ѱ�����\n", info.name);
			}
		}

	} while (FindNextFileA(FindHandle, &FileInfo));
}
// ���ò������
void Plugin::InitAllPlugin()
{
	// ������������ö�Ӧ�ĺ���
	for (auto& plugin : m_plugins)
	{
		PFUNC2 func = (PFUNC2)GetProcAddress(plugin.Base, "run");
		if (func) func();
	}
}
// ���ж��
void Plugin::ReleasePlg()
{
	// �������д������
	for (auto& plugin : m_plugins)
	{
		FreeLibrary(plugin.Base);
	}
}

