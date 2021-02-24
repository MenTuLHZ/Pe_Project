//Pe_Read.h
#ifndef  PE_READ_H
#define PE_READ_H
#include <windows.h>
//------------------------------------------------------------------
//IMAGE_FILE_HEADER arg:pe_buffer peNT头
IMAGE_NT_HEADERS* Get_IMAGE_NT_HEADERS(BYTE* _pe_buffer);
DWORD Get_Signature(IMAGE_NT_HEADERS* _nt_headers);

//------------------------------------------------------------------
//IMAGE_FILE_HEADER arg:pe_buffer （pe文件头）
IMAGE_FILE_HEADER* Get_IMAGE_FILE_HEADER(IMAGE_NT_HEADERS* _nt_headers);
WORD Get_Machine(IMAGE_FILE_HEADER* _file_header);
WORD Get_NumberOfSections(IMAGE_FILE_HEADER* _file_header);
DWORD Get_TimeDateStamp(IMAGE_FILE_HEADER* _file_header);
WORD Get_SizeOfOptionHeader(IMAGE_FILE_HEADER* _file_header);

//------------------------------------------------------------------
//IMAGE_OPTIONAL_HEADER arg:ne_header （可选pe头）
IMAGE_OPTIONAL_HEADER* Get_IMAGE_OPTIONAL_HEADER(IMAGE_NT_HEADERS* _nt_headers);
WORD Get_Magic(IMAGE_OPTIONAL_HEADER* _OPTIONAL_HEADER);
DWORD Get_SizeOfCode(IMAGE_OPTIONAL_HEADER* _OPTIONAL_HEADER);
DWORD Get_AddressOfEntryPoint(IMAGE_OPTIONAL_HEADER* _OPTIONAL_HEADER);
DWORD Get_BaseOfCode(IMAGE_OPTIONAL_HEADER* _OPTIONAL_HEADER);
DWORD Get_BaseOfData(IMAGE_OPTIONAL_HEADER* _OPTIONAL_HEADER);
DWORD Get_ImageBase(IMAGE_OPTIONAL_HEADER* _OPTIONAL_HEADER);
DWORD Get_SectionAlignment(IMAGE_OPTIONAL_HEADER* _OPTIONAL_HEADER);
DWORD Get_FileAlignment(IMAGE_OPTIONAL_HEADER* _OPTIONAL_HEADER);
DWORD Get_SizeOfImage(IMAGE_OPTIONAL_HEADER* _OPTIONAL_HEADER);
DWORD Get_SizeOfHeaders(IMAGE_OPTIONAL_HEADER* _OPTIONAL_HEADER);
IMAGE_DATA_DIRECTORY* Get_IMAGE_DATA_DIRECTORY(IMAGE_OPTIONAL_HEADER* _OPTIONAL_HEADER);

//------------------------------------------------------------------
//IMAGE_SECTION_HEADER arg:pe_buffer （节表）
IMAGE_SECTION_HEADER* Get_IMAGE_SECTION_HEADER(BYTE* _pe_buffer);

//------------------------------------------------------------------
//IMAGE_EXPORT_DIRECTORY arg:IMAGE_OPTIONAL_HEADER （导出表）
IMAGE_EXPORT_DIRECTORY* Get_IMAGE_EXPORT_DIRECTORY(IMAGE_OPTIONAL_HEADER* _OPTIONAL_HEADER);

//------------------------------------------------------------------
//IMAGE_IMPORT_DESCRIPTOR arg:IMAGE_OPTIONAL_HEADER （导入表）
IMAGE_IMPORT_DESCRIPTOR* Get_IMAGE_IMPORT_DESCRIPTOR(IMAGE_OPTIONAL_HEADER* _OPTIONAL_HEADER);

//------------------------------------------------------------------
//IMAGE_BASE_RELOCATION arg:IMAGE_OPTIONAL_HEADER （重定位表）
IMAGE_BASE_RELOCATION* Get_IMAGE_BASE_RELOCATION(IMAGE_OPTIONAL_HEADER* _OPTIONAL_HEADER);

//------------------------------------------------------------------
//IMAGE_BASE_RELOCATION arg:IMAGE_OPTIONAL_HEADER （重定位表）
IMAGE_RESOURCE_DIRECTORY* Get_IMAGE_RESOURCE_DIRECTORY(IMAGE_OPTIONAL_HEADER* _OPTIONAL_HEADER);


//pe加载
typedef struct _Pe_Load
{
	void Init_Size(BYTE* _pe_buffer);
	void Load_Pe(BYTE* _pe_buffer);

	DWORD buffer_size;
	BYTE* peLoad_buffer;
}Pe_Load;

#endif // ! 
