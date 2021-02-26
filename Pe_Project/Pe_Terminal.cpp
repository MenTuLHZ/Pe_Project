// Pe_Project.cpp : 此文件包含 "main" 函数。程序执行将在此处开始并结束。
//
#define _CRT_SECURE_NO_WARNINGS

#include <iostream>
#include <windows.h>
#include "Pe_Read.h"
#include <time.h>

// break:true Continue:false
bool Console_BreakOrExitOrContinue()
{
	while (true)
	{
		char cmd[MAX_PATH];
		memset(cmd, 0, MAX_PATH);
		printf("输入c继续,b返回,e退出:");
		scanf("%s", cmd);
		cmd[MAX_PATH - 1] = 0;
		if (!strcmp(cmd, "b"))
		{
			return true;
		}
		if (!strcmp(cmd, "c"))
		{
			return false;
		}
		if (!strcmp(cmd, "e"))
		{
			exit(0);
		}
		printf("输入有误请重新输入\r\n");
	}

}

void ConsoleWrite_PeHeader(Pe_Load* _pe_load)
{
	BYTE* _file_buffer = _pe_load->file_buffer;

	IMAGE_NT_HEADERS* _nt_headers = Get_IMAGE_NT_HEADERS(_pe_load->file_buffer);
	IMAGE_FILE_HEADER* _file_header = Get_IMAGE_FILE_HEADER(_file_buffer);
	IMAGE_OPTIONAL_HEADER* _optional_header = Get_IMAGE_OPTIONAL_HEADER(_pe_load->file_buffer);
	while (true)
	{

		//oep
		printf("EntryPoint:0x%X\r\n", Get_AddressOfEntryPoint(_optional_header));

		//ImageBase
		printf("ImageBase:0x%X\r\n", Get_ImageBase(_optional_header));

		//SizeOfImage
		printf("SizeOfImage:0x%X\r\n", Get_SizeOfImage(_optional_header));

		//BaseOfCode
		printf("BaseOfCode:0x%X\r\n", Get_BaseOfCode(_optional_header));

		//BaseOfData
		printf("BaseOfData:0x%X\r\n", Get_BaseOfData(_optional_header));

		//SectionAlignment
		printf("SectionAlignment:0x%X\r\n", Get_SectionAlignment(_optional_header));

		//FileAlignment
		printf("FileAlignment:0x%X\r\n", Get_FileAlignment(_optional_header));

		//FileAlignment
		printf("FileAlignment:0x%X\r\n", Get_Magic(_optional_header));

		//Subsystem
		printf("Subsystem:0x%X\r\n", Get_Subsystem(_optional_header));

		//NumberOfSections
		printf("NumberOfSections:0x%X\r\n", Get_NumberOfSections(_file_buffer));

		//TimeDateStamp
		struct tm* _time;
		time_t rawtime;
		char now[64];
		rawtime = Get_TimeDateStamp(_file_header);
		_time = localtime(&rawtime);
		strftime(now, 64, "%Y-%m-%d %H:%M:%S", _time);
		printf("TimeDateStamp：%s\r\n", now);

		//SizeOfOptionHeader
		printf("SizeOfOptionHeader:0x%X\r\n", Get_SizeOfOptionHeader(_file_header));

		if (Console_BreakOrExitOrContinue())
		{
			system("cls");
			break;
		}
	}
}

void ConsoleWrite_PeSection(Pe_Load* _pe_load)
{
	BYTE* _file_buffer = _pe_load->file_buffer;

	IMAGE_NT_HEADERS* _nt_headers = Get_IMAGE_NT_HEADERS(_pe_load->file_buffer);
	IMAGE_FILE_HEADER* _file_header = Get_IMAGE_FILE_HEADER(_file_buffer);
	IMAGE_OPTIONAL_HEADER* _optional_header = Get_IMAGE_OPTIONAL_HEADER(_pe_load->file_buffer);

	char _section_name[IMAGE_SIZEOF_SHORT_NAME + 1];
	memset(_section_name, 0, sizeof(_section_name));

	int section_count = Get_NumberOfSections(_file_buffer);
	while (true)
	{

		for (size_t i = 0; i < section_count; i++)
		{
			IMAGE_SECTION_HEADER* _section_heaer = (IMAGE_SECTION_HEADER*)&((BYTE*)_optional_header)[((DWORD)_file_header->SizeOfOptionalHeader) + i * sizeof(IMAGE_SECTION_HEADER)];
			memcpy(_section_name, _section_heaer->Name, IMAGE_SIZEOF_SHORT_NAME);

			//sectionName
			printf("\r\n---------------------------\
			\r\nSectionName:%s\
			\nRVA:0x%X VirtualSize:0x%X\
			\nFOA:0x%X SizeOfRawData:0x%X\
			\nCharacteristics:0x%X\r\n",
				_section_name,
				_section_heaer->VirtualAddress,
				_section_heaer->Misc.VirtualSize,
				_section_heaer->PointerToRawData,
				_section_heaer->SizeOfRawData,
				_section_heaer->Characteristics
			);
		}
		if (Console_BreakOrExitOrContinue())
		{
			system("cls");
			break;
		}
	}
}

void ConsoleWrite_Import(Pe_Load* _pe_load)
{
	BYTE* _file_buffer = _pe_load->file_buffer;
	IMAGE_OPTIONAL_HEADER* _optional_header = Get_IMAGE_OPTIONAL_HEADER(_pe_load->file_buffer);

	IMAGE_IMPORT_DESCRIPTOR* import_descriptor = Get_IMAGE_IMPORT_DESCRIPTOR(_file_buffer);
	bool is_NotOver = true;
	int count = 0;
	DWORD* int_p = NULL;
	while (is_NotOver)
	{
		for (size_t i = 0; i < sizeof(IMAGE_IMPORT_DESCRIPTOR); i++)
		{
			if (((char*)import_descriptor)[i] != 0)
			{
				is_NotOver = true;
				count++; break;
			}
			else
			{
				is_NotOver = false;
			}
		}
		if (is_NotOver == false) { break; }
		import_descriptor++;
	}



	int index = 0;
	while (true)
	{
		printf("共有%d个Dll\r\n", count);
		printf("请输入要查看第几个dll:");
		scanf("%d", &index);

		if ((index > 0) && (index <= count))
		{
			import_descriptor = &Get_IMAGE_IMPORT_DESCRIPTOR(_file_buffer)[index - 1];
			printf("第<%d>个导入表\r\n", index);
			printf("OriginalFifstThunk:%X\r\n", import_descriptor->OriginalFirstThunk);
			printf("TimeDataStamp:%X\r\n", import_descriptor->TimeDateStamp);
			printf("ForwarDerChain:%d\r\n", import_descriptor->ForwarderChain);
			printf("Dll Name:%s\r\n", &_pe_load->file_buffer[FOA_TO_RVA(_pe_load->file_buffer, import_descriptor->Name)]);
			printf("FirstThunk:%X\r\n", import_descriptor->FirstThunk);
			int_p = (DWORD*)&_pe_load->file_buffer[FOA_TO_RVA(_pe_load->file_buffer, import_descriptor->OriginalFirstThunk)];
			while (true)
			{
				if (*int_p == NULL) { break; }
				else
				{
					if (((*int_p) & 0x80000000) != 0)
					{
						printf("导出序号为:%X\r\n", (*int_p & 0x7FFFFFFF));
					}
					else
					{
						DWORD foa = FOA_TO_RVA(_pe_load->file_buffer, *int_p);
						printf("导出函数名为:%s\r\n", &(((char*)&_pe_load->file_buffer[FOA_TO_RVA(_pe_load->file_buffer, *int_p)])[2]));
					}
					int_p++;
				}
			}
			printf("-----------------\r\n");
			if (import_descriptor->TimeDateStamp == -1) {
				printf("已绑定\r\n");
				IMAGE_BOUND_IMPORT_DESCRIPTOR* bound_import_descriptor_p = Get_IMAGE_BOUND_IMPORT_DESCRIPTOR(_pe_load->file_buffer);
				//缺少已绑定的程序没有写后续
			}
			else
			{
				printf("未绑定\r\n");
			}
			printf("-----------------\r\n");
		}
		if (Console_BreakOrExitOrContinue())
		{
			system("cls");
			return;
		}
	}
}

enum class CMD
{
	over = 0,
	PeHeader = 1,
	PeSection = 2,
	Import =  4,

}_cmd;

int main()
{
	char* file_name = new char[MAX_PATH];
	printf("请把目标文件拖拽到cmd以自动填写路径或手动填写路径,路径准备好请按Enter.\r\n");
	if (scanf("%s", file_name) == EOF)
	{
		MessageBoxA(NULL, "输入错误", "ERROR", MB_OK);
		return 0;
	}
	HANDLE file_headle = CreateFileA(file_name,
		GENERIC_READ | GENERIC_WRITE,
		0,
		NULL,
		OPEN_ALWAYS,
		FILE_ATTRIBUTE_NORMAL,
		NULL);
	DWORD file_size = GetFileSize(file_headle, NULL);
	BYTE* file_buffer = (BYTE*)malloc(file_size);
	DWORD out_r_f_n = 0;
	if (!ReadFile(file_headle, file_buffer, file_size, &out_r_f_n, NULL))
	{
		MessageBoxA(NULL, "读取文件错误", "ERROR", MB_OK);
		return NULL;
	}
	CloseHandle(file_headle);

	Pe_Load _peLoad;
	_peLoad.Init(file_buffer, file_size);
	_cmd = CMD::over;
	while (true)
	{
		printf("输入:1查看PeHeader,2查看PeSection,4查看Import,0退出.\r\n");
		if (scanf("%d", &_cmd) == EOF)
		{
			MessageBoxA(NULL, "输入错误", "ERROR", MB_OK);
			return 0;
		}
		switch (_cmd)
		{
		case CMD::over:
			return 0;
		case CMD::PeHeader:
			ConsoleWrite_PeHeader(&_peLoad);
			break;
		case CMD::PeSection:
			ConsoleWrite_PeSection(&_peLoad);
			break;
		case CMD::Import:
			ConsoleWrite_Import(&_peLoad);
			break;
		default:
			system("cls");
			_cmd = CMD::over;
			break;
		}
		
	}
	return 0;
}