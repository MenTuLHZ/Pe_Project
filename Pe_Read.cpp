#include<iostream>
#include <windows.h>

//------------------------------------------------------------------
//IMAGE_FILE_HEADER arg:pe_buffer peNTͷ
IMAGE_NT_HEADERS* Get_IMAGE_NT_HEADERS(BYTE* _pe_buffer)
{
	return (IMAGE_NT_HEADERS*)((DWORD)_pe_buffer+(DWORD)_pe_buffer[0x3c]);
}

DWORD Get_Signature(IMAGE_NT_HEADERS* _nt_headers)
{
	return _nt_headers->Signature;
}


//------------------------------------------------------------------
//IMAGE_FILE_HEADER arg:pe_buffer ��pe�ļ�ͷ��
IMAGE_FILE_HEADER* Get_IMAGE_FILE_HEADER(IMAGE_NT_HEADERS* _nt_headers)
{
	return (&_nt_headers->FileHeader);
}

WORD Get_Machine(IMAGE_FILE_HEADER* _file_header)
{
	return _file_header->Machine;
}

WORD Get_NumberOfSections(IMAGE_FILE_HEADER* _file_header)
{
	return _file_header->NumberOfSections;
}

DWORD Get_TimeDateStamp(IMAGE_FILE_HEADER* _file_header)
{
	return _file_header->TimeDateStamp;
}

WORD Get_SizeOfOptionHeader(IMAGE_FILE_HEADER* _file_header)
{
	return _file_header->SizeOfOptionalHeader;
}

//------------------------------------------------------------------
//IMAGE_OPTIONAL_HEADER arg:ne_header ����ѡpeͷ��
IMAGE_OPTIONAL_HEADER* Get_IMAGE_OPTIONAL_HEADER(IMAGE_NT_HEADERS* _nt_headers)
{
	return &_nt_headers->OptionalHeader;
}

WORD Get_Magic(IMAGE_OPTIONAL_HEADER* _OPTIONAL_HEADER)
{
	return _OPTIONAL_HEADER->Magic;
}

DWORD Get_SizeOfCode(IMAGE_OPTIONAL_HEADER* _OPTIONAL_HEADER)
{
	return _OPTIONAL_HEADER->SizeOfCode;
}

DWORD Get_AddressOfEntryPoint(IMAGE_OPTIONAL_HEADER* _OPTIONAL_HEADER)
{
	return _OPTIONAL_HEADER->AddressOfEntryPoint;
}

DWORD Get_BaseOfCode(IMAGE_OPTIONAL_HEADER* _OPTIONAL_HEADER)
{
	return _OPTIONAL_HEADER->BaseOfCode;
}

DWORD Get_BaseOfData(IMAGE_OPTIONAL_HEADER* _OPTIONAL_HEADER)
{
	return _OPTIONAL_HEADER->BaseOfData;
}

DWORD Get_ImageBase(IMAGE_OPTIONAL_HEADER* _OPTIONAL_HEADER)
{
	return _OPTIONAL_HEADER->ImageBase;
}

DWORD Get_SectionAlignment(IMAGE_OPTIONAL_HEADER* _OPTIONAL_HEADER)
{
	return _OPTIONAL_HEADER->SectionAlignment;
}

DWORD Get_FileAlignment(IMAGE_OPTIONAL_HEADER* _OPTIONAL_HEADER)
{
	return _OPTIONAL_HEADER->FileAlignment;
}

DWORD Get_SizeOfImage(IMAGE_OPTIONAL_HEADER* _OPTIONAL_HEADER)
{
	return _OPTIONAL_HEADER->SizeOfImage;
}

DWORD Get_SizeOfHeaders(IMAGE_OPTIONAL_HEADER* _OPTIONAL_HEADER)
{
	return _OPTIONAL_HEADER->SizeOfHeaders;
}

IMAGE_DATA_DIRECTORY* Get_IMAGE_DATA_DIRECTORY(IMAGE_OPTIONAL_HEADER* _OPTIONAL_HEADER)
{
	return _OPTIONAL_HEADER->DataDirectory;
}

//------------------------------------------------------------------
//IMAGE_SECTION_HEADER arg:pe_buffer ���ڱ�
IMAGE_SECTION_HEADER* Get_IMAGE_SECTION_HEADER(BYTE* _pe_buffer)
{
	IMAGE_NT_HEADERS* _nt_headers = Get_IMAGE_NT_HEADERS(_pe_buffer);
	return (IMAGE_SECTION_HEADER*)&_pe_buffer[DWORD(_nt_headers->FileHeader.SizeOfOptionalHeader)
		+ ((DWORD)Get_IMAGE_OPTIONAL_HEADER(_nt_headers) - (DWORD)_pe_buffer)];
}

//------------------------------------------------------------------
//IMAGE_EXPORT_DIRECTORY arg:IMAGE_OPTIONAL_HEADER ��������
IMAGE_EXPORT_DIRECTORY* Get_IMAGE_EXPORT_DIRECTORY(IMAGE_OPTIONAL_HEADER* _OPTIONAL_HEADER)
{
	return (IMAGE_EXPORT_DIRECTORY*)&_OPTIONAL_HEADER[IMAGE_DIRECTORY_ENTRY_EXPORT];
}

//------------------------------------------------------------------
//IMAGE_IMPORT_DESCRIPTOR arg:IMAGE_OPTIONAL_HEADER �������
IMAGE_IMPORT_DESCRIPTOR* Get_IMAGE_IMPORT_DESCRIPTOR(IMAGE_OPTIONAL_HEADER* _OPTIONAL_HEADER)
{
	return (IMAGE_IMPORT_DESCRIPTOR*)&_OPTIONAL_HEADER[IMAGE_DIRECTORY_ENTRY_IMPORT];
}

//------------------------------------------------------------------
//IMAGE_BASE_RELOCATION arg:IMAGE_OPTIONAL_HEADER ���ض�λ��
IMAGE_BASE_RELOCATION* Get_IMAGE_BASE_RELOCATION(IMAGE_OPTIONAL_HEADER* _OPTIONAL_HEADER)
{
	return (IMAGE_BASE_RELOCATION*)&_OPTIONAL_HEADER[IMAGE_DIRECTORY_ENTRY_BASERELOC];
}

//------------------------------------------------------------------
//IMAGE_BASE_RELOCATION arg:IMAGE_OPTIONAL_HEADER ���ض�λ��
IMAGE_RESOURCE_DIRECTORY* Get_IMAGE_RESOURCE_DIRECTORY(IMAGE_OPTIONAL_HEADER* _OPTIONAL_HEADER)
{
	return (IMAGE_RESOURCE_DIRECTORY*)&_OPTIONAL_HEADER[IMAGE_DIRECTORY_ENTRY_RESOURCE];
}

typedef struct _Pe_Load
{
	void Init_Size(BYTE* _pe_buffer)
	{
		this->buffer_size = Get_IMAGE_OPTIONAL_HEADER(Get_IMAGE_NT_HEADERS(_pe_buffer))->SizeOfImage;
		this->peLoad_buffer = (BYTE*)malloc(this->buffer_size);
	}

	void Load_Pe(BYTE* _pe_buffer)
	{
		IMAGE_NT_HEADERS* _nt_headers = Get_IMAGE_NT_HEADERS(_pe_buffer);
		IMAGE_OPTIONAL_HEADER* _optional_header = Get_IMAGE_OPTIONAL_HEADER(_nt_headers);

		//����dosͷ+NTͷ+�ڱ��ܺ� fileAligment����
		int i = 0;
		for (; i < _optional_header->SizeOfHeaders; i++)
		{
			this->peLoad_buffer[i] = _pe_buffer[i];
		}
		i = 0;
		//end
		//���������
	}
	DWORD buffer_size;
	BYTE* peLoad_buffer;

}Pe_Load;


int main()
{
	HANDLE h1 = CreateFileA("C:\\Users\\Administrator\\Desktop\\ipmsg.exe",
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