//Pe_Read.cpp
#include "Pe_read.h"

//------------------------------------------------------------------
//IMAGE_FILE_HEADER arg:pe_buffer peNT头
IMAGE_NT_HEADERS* Get_IMAGE_NT_HEADERS(BYTE* _pe_buffer)
{
	return (IMAGE_NT_HEADERS*)((DWORD)_pe_buffer+(DWORD)_pe_buffer[0x3c]);
}

DWORD Get_Signature(IMAGE_NT_HEADERS* _nt_headers)
{
	return _nt_headers->Signature;
}


//------------------------------------------------------------------
//IMAGE_FILE_HEADER arg:pe_buffer （pe文件头）
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
//IMAGE_OPTIONAL_HEADER arg:ne_header （可选pe头）
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
//IMAGE_SECTION_HEADER arg:pe_buffer （节表）
IMAGE_SECTION_HEADER* Get_IMAGE_SECTION_HEADER(BYTE* _pe_buffer)
{
	IMAGE_NT_HEADERS* _nt_headers = Get_IMAGE_NT_HEADERS(_pe_buffer);
	return (IMAGE_SECTION_HEADER*)&_pe_buffer[DWORD(_nt_headers->FileHeader.SizeOfOptionalHeader)
		+ ((DWORD)Get_IMAGE_OPTIONAL_HEADER(_nt_headers) - (DWORD)_pe_buffer)];
}

//------------------------------------------------------------------
//IMAGE_EXPORT_DIRECTORY arg:IMAGE_OPTIONAL_HEADER （导出表）
IMAGE_EXPORT_DIRECTORY* Get_IMAGE_EXPORT_DIRECTORY(IMAGE_OPTIONAL_HEADER* _OPTIONAL_HEADER)
{
	return (IMAGE_EXPORT_DIRECTORY*)&_OPTIONAL_HEADER[IMAGE_DIRECTORY_ENTRY_EXPORT];
}

//------------------------------------------------------------------
//IMAGE_IMPORT_DESCRIPTOR arg:IMAGE_OPTIONAL_HEADER （导入表）
IMAGE_IMPORT_DESCRIPTOR* Get_IMAGE_IMPORT_DESCRIPTOR(IMAGE_OPTIONAL_HEADER* _OPTIONAL_HEADER)
{
	return (IMAGE_IMPORT_DESCRIPTOR*)&_OPTIONAL_HEADER[IMAGE_DIRECTORY_ENTRY_IMPORT];
}

//------------------------------------------------------------------
//IMAGE_BASE_RELOCATION arg:IMAGE_OPTIONAL_HEADER （重定位表）
IMAGE_BASE_RELOCATION* Get_IMAGE_BASE_RELOCATION(IMAGE_OPTIONAL_HEADER* _OPTIONAL_HEADER)
{
	return (IMAGE_BASE_RELOCATION*)&_OPTIONAL_HEADER[IMAGE_DIRECTORY_ENTRY_BASERELOC];
}

//------------------------------------------------------------------
//IMAGE_BASE_RELOCATION arg:IMAGE_OPTIONAL_HEADER （重定位表）
IMAGE_RESOURCE_DIRECTORY* Get_IMAGE_RESOURCE_DIRECTORY(IMAGE_OPTIONAL_HEADER* _OPTIONAL_HEADER)
{
	return (IMAGE_RESOURCE_DIRECTORY*)&_OPTIONAL_HEADER[IMAGE_DIRECTORY_ENTRY_RESOURCE];
}


void _Pe_Load::Init_Size(BYTE* _pe_buffer)
{
	this->buffer_size = Get_IMAGE_OPTIONAL_HEADER(Get_IMAGE_NT_HEADERS(_pe_buffer))->SizeOfImage;
	this->peLoad_buffer = (BYTE*)malloc(this->buffer_size);
}

void _Pe_Load::Load_Pe(BYTE* _pe_buffer)
{
	IMAGE_NT_HEADERS* _nt_headers = Get_IMAGE_NT_HEADERS(_pe_buffer);
	IMAGE_FILE_HEADER* _file_header = Get_IMAGE_FILE_HEADER(_nt_headers);
	IMAGE_OPTIONAL_HEADER* _optional_header = Get_IMAGE_OPTIONAL_HEADER(_nt_headers);

	//复制dos头+NT头+节表总和 fileAligment对齐
	int i = 0;
	for (; i < _optional_header->SizeOfHeaders; i++)
	{
		this->peLoad_buffer[i] = _pe_buffer[i];
	}
	i = 0;
	//end

	//int end_virtual = 0;
	//int end_file = 0;

	//拉伸节数据
	for (; i < _file_header->NumberOfSections; i++)
	{
		IMAGE_SECTION_HEADER* section_header = (IMAGE_SECTION_HEADER*)&((BYTE*)_optional_header)[((DWORD)_file_header->SizeOfOptionalHeader)+ i * sizeof(IMAGE_SECTION_HEADER)];
		int section_RVA_baseAddress = section_header->VirtualAddress;
		int section_FOA_baseAddress = section_header->PointerToRawData;
		size_t k = 0;
		for (; k < section_header->SizeOfRawData; k++)
		{
			this->peLoad_buffer[section_RVA_baseAddress + k] = _pe_buffer[section_FOA_baseAddress + k];
			
		}
		//end_virtual = section_RVA_baseAddress + k;
		//end_file = section_FOA_baseAddress + k;
	}
	//end

	/*
	i = 0;
	//check end file
	if (end_virtual != this->buffer_size)
	{
		int length = this->buffer_size - end_virtual;
		for (; i < length; i++)
		{
			this->peLoad_buffer[end_virtual + i] = _pe_buffer[end_file + i];
		}
	}
	//end
	*/
	return;
}
