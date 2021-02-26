//Pe_Read.cpp
#include "Pe_read.h"

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
IMAGE_FILE_HEADER* Get_IMAGE_FILE_HEADER(BYTE* file_buffer)
{
	return &Get_IMAGE_NT_HEADERS(file_buffer)->FileHeader;
}

WORD Get_Machine(IMAGE_FILE_HEADER* _file_header)
{
	return _file_header->Machine;
}

WORD Get_NumberOfSections(BYTE* _file_buffer)
{
	return Get_IMAGE_FILE_HEADER(_file_buffer)->NumberOfSections;
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
IMAGE_OPTIONAL_HEADER* Get_IMAGE_OPTIONAL_HEADER(BYTE* _pe_buffer)
{
	return &Get_IMAGE_NT_HEADERS(_pe_buffer)->OptionalHeader;
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

WORD Get_Subsystem(IMAGE_OPTIONAL_HEADER* _OPTIONAL_HEADER)
{
	return _OPTIONAL_HEADER->Subsystem;
}



IMAGE_DATA_DIRECTORY* Get_IMAGE_DATA_DIRECTORY(BYTE* _file_buffer)
{
	return (IMAGE_DATA_DIRECTORY*)(&Get_IMAGE_OPTIONAL_HEADER(_file_buffer)->DataDirectory);
}

//------------------------------------------------------------------
//IMAGE_SECTION_HEADER arg:pe_buffer ���ڱ�
IMAGE_SECTION_HEADER* Get_IMAGE_SECTION_HEADER(BYTE* _pe_buffer)
{
	return (IMAGE_SECTION_HEADER*)&_pe_buffer[DWORD(Get_IMAGE_NT_HEADERS(_pe_buffer)->FileHeader.SizeOfOptionalHeader)
		+ ((DWORD)Get_IMAGE_OPTIONAL_HEADER(_pe_buffer) - (DWORD)_pe_buffer)];
}

//------------------------------------------------------------------
//IMAGE_EXPORT_DIRECTORY arg:IMAGE_OPTIONAL_HEADER ��������
IMAGE_EXPORT_DIRECTORY* Get_IMAGE_EXPORT_DIRECTORY(BYTE* _file_buffer)
{
	return (IMAGE_EXPORT_DIRECTORY*)&_file_buffer[FOA_TO_RVA(_file_buffer,
		Get_IMAGE_DATA_DIRECTORY(_file_buffer)[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress)];
}

//------------------------------------------------------------------
//IMAGE_IMPORT_DESCRIPTOR arg:IMAGE_OPTIONAL_HEADER �������
IMAGE_IMPORT_DESCRIPTOR* Get_IMAGE_IMPORT_DESCRIPTOR(BYTE* _file_buffer)
{
	return (IMAGE_IMPORT_DESCRIPTOR*)&_file_buffer[FOA_TO_RVA(_file_buffer,
		Get_IMAGE_DATA_DIRECTORY(_file_buffer)[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress)];
}

//------------------------------------------------------------------
//IMAGE_BASE_RELOCATION arg:IMAGE_OPTIONAL_HEADER ���ض�λ��
IMAGE_BASE_RELOCATION* Get_IMAGE_BASE_RELOCATION(BYTE* _file_buffer)
{
	return (IMAGE_BASE_RELOCATION*)&_file_buffer[FOA_TO_RVA(_file_buffer,
		Get_IMAGE_DATA_DIRECTORY(_file_buffer)[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress)];
}

//------------------------------------------------------------------
//IMAGE_BASE_RELOCATION arg:IMAGE_OPTIONAL_HEADER ����Դ��
IMAGE_RESOURCE_DIRECTORY* Get_IMAGE_RESOURCE_DIRECTORY(BYTE* _file_buffer)
{
	return (IMAGE_RESOURCE_DIRECTORY*)&_file_buffer[FOA_TO_RVA(_file_buffer,
		Get_IMAGE_DATA_DIRECTORY(_file_buffer)[IMAGE_DIRECTORY_ENTRY_RESOURCE].VirtualAddress)];
}


IMAGE_BOUND_IMPORT_DESCRIPTOR* Get_IMAGE_BOUND_IMPORT_DESCRIPTOR(BYTE* _file_buffer)
{
	return (IMAGE_BOUND_IMPORT_DESCRIPTOR*)&_file_buffer[FOA_TO_RVA(_file_buffer,
		Get_IMAGE_DATA_DIRECTORY(_file_buffer)[IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT].VirtualAddress)];
}

DWORD Get_e_lfanew_DWORD(BYTE* file_buffer)
{
	return *(DWORD*)&file_buffer[0x3c];
}

DWORD Get_VirtualSize(BYTE* file_buffer, WORD section_index)
{
	return *(DWORD*)&(Get_IMAGE_SECTION_HEADER(file_buffer)[0x08 + (section_index * 0x28)]);
}

DWORD Get_VirtualAddress(BYTE* file_buffer, WORD section_index)
{
	return *(DWORD*)&(Get_IMAGE_SECTION_HEADER(file_buffer)[0x0c + (section_index * 0x28)]);
}

DWORD Get_SizeOfRawData(BYTE* file_buffer, WORD section_index)
{
	return *(DWORD*)&(Get_IMAGE_SECTION_HEADER(file_buffer)[0x10 + (section_index * 0x28)]);
}

DWORD Get_PointerToRawData(BYTE* file_buffer, WORD section_index)
{
	return *(DWORD*)&(Get_IMAGE_SECTION_HEADER(file_buffer)[0x14 + (section_index * 0x28)]);
}


DWORD ImageAddressOffset_Add_ImageBase(BYTE* file_buffer, WORD section_index)
{
	return (Get_VirtualAddress(file_buffer, section_index) + Get_ImageBase(Get_IMAGE_OPTIONAL_HEADER(file_buffer)));
}

// rva to roa arg1:file_buffer arg2:rva return foa
DWORD RVA_To_FOA(BYTE* file_buffer, DWORD RVA)
{
	RVA += Get_ImageBase(Get_IMAGE_OPTIONAL_HEADER(file_buffer));
	for (size_t i = 0; i < Get_NumberOfSections(file_buffer); i++)
	{
		DWORD virtual_address = ImageAddressOffset_Add_ImageBase(file_buffer, i), sizeof_seciton_in_a_file = Get_SizeOfRawData(file_buffer, i);
		if ((virtual_address <= RVA) && (virtual_address + sizeof_seciton_in_a_file > RVA))
		{
			return RVA - virtual_address + Get_PointerToRawData(file_buffer, i);
		}
	}
	return RVA;
}

// roa to foa arg1:file_buffer arg2:foa retrun:rva
DWORD FOA_TO_RVA(BYTE* file_buffer, DWORD FOA)
{
    for (size_t i = 0; i < Get_NumberOfSections(file_buffer); i++)
    {
        DWORD Address_in_a_file = Get_PointerToRawData(file_buffer, i), sizeof_seciton_in_a_file = Get_SizeOfRawData(file_buffer, i);
        if ((Address_in_a_file <= FOA) && (Address_in_a_file + sizeof_seciton_in_a_file > FOA))
        {
            return  FOA - Address_in_a_file + Get_VirtualAddress(file_buffer, i);
        }
    }
    return FOA;
}

void _Pe_Load::Init(BYTE* _file_buffer,DWORD _file_buffer_size)
{
	this->peLoad_buffer_size = Get_IMAGE_OPTIONAL_HEADER(_file_buffer)->SizeOfImage;
	this->file_buffer = _file_buffer;
	this->file_buffer_size = _file_buffer_size;
}

void _Pe_Load::Load_Pe(BYTE* _pe_buffer)
{
	this->peLoad_buffer = (BYTE*)malloc(this->peLoad_buffer_size);
	IMAGE_NT_HEADERS* _nt_headers = Get_IMAGE_NT_HEADERS(_pe_buffer);
	IMAGE_FILE_HEADER* _file_header = Get_IMAGE_FILE_HEADER(_pe_buffer);
	IMAGE_OPTIONAL_HEADER* _optional_header = Get_IMAGE_OPTIONAL_HEADER(_pe_buffer);

	//����dosͷ+NTͷ+�ڱ��ܺ� fileAligment����
	int i = 0;
	for (; i < _optional_header->SizeOfHeaders; i++)
	{
		this->peLoad_buffer[i] = _pe_buffer[i];
	}
	i = 0;
	//end

	//int end_virtual = 0;
	//int end_file = 0;

	//���������
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
