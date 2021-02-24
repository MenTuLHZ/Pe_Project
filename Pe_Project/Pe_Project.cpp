// Pe_Project.cpp : 此文件包含 "main" 函数。程序执行将在此处开始并结束。
//

#include <iostream>
#include <windows.h>
#include "Pe_Read.h"


int main()
{
	HANDLE h1 = CreateFileA("C:\\Users\\Administrator\\Desktop\\sysdiag-all-5.0.57.0-20210220.exe",
		GENERIC_READ | GENERIC_WRITE,
		0,
		NULL,
		OPEN_ALWAYS,
		FILE_ATTRIBUTE_NORMAL,
		NULL);
	DWORD e = GetFileSize(h1, NULL);
	BYTE* c = (BYTE*)malloc(e);
	DWORD out_r_f_n = 0;
	if (ReadFile(h1, c, e, &out_r_f_n, NULL))
	{

	}
	CloseHandle(h1);
	Pe_Load _peLoad;
	_peLoad.Init_Size(c);
	_peLoad.Load_Pe(c);
	return 0;
}