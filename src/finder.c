#include "finder.h"
#include "gadget.h"

void find_read_gadget_module(LPVOID module,char ** gadget, int * gadget_offset, char * gadget_negative){ 
    DWORD oldprotect = 0;
	PIMAGE_DOS_HEADER pImgDOSHead = (PIMAGE_DOS_HEADER) module;
	PIMAGE_NT_HEADERS pImgNTHead = (PIMAGE_NT_HEADERS)((DWORD_PTR) module + pImgDOSHead->e_lfanew);
	int i;
	
	// find .text section
	for (i = 0; i < pImgNTHead->FileHeader.NumberOfSections; i++) {
		PIMAGE_SECTION_HEADER pImgSectionHead = (PIMAGE_SECTION_HEADER)((DWORD_PTR)IMAGE_FIRST_SECTION(pImgNTHead) + ((DWORD_PTR)IMAGE_SIZEOF_SECTION_HEADER * i));
        char text_section[] = {'.','t','e','x','t',0};
		if (!help_strcmp_f((char *)pImgSectionHead->Name,text_section)) {
			
			void * module_text_segment = (char*) module + pImgSectionHead->VirtualAddress;
			int module_size = pImgSectionHead->Misc.VirtualSize;

            int offset = 0;
            char * gadget_return;
            char * negative;
            gadget_return = (char*) module_text_segment + find_mov_req_qword_ptr(module_text_segment,module_size,&offset,&negative);
            
            *gadget_offset = offset;
            *gadget_negative = negative;
            if(gadget_return == module_text_segment){
                // If the offset returned is zero then it means the gadget is not in the specified address range
                // We do this in case we would want to loop through others
                *gadget = NULL;
            }else{
                *gadget = gadget_return;
            }

		}
	}
}

void find_write_gadget_module(LPVOID module,char ** gadget, int * gadget_offset, char * gadget_negative){ 
    DWORD oldprotect = 0;
	PIMAGE_DOS_HEADER pImgDOSHead = (PIMAGE_DOS_HEADER) module;
	PIMAGE_NT_HEADERS pImgNTHead = (PIMAGE_NT_HEADERS)((DWORD_PTR) module + pImgDOSHead->e_lfanew);
	int i;
	
	// find .text section
	for (i = 0; i < pImgNTHead->FileHeader.NumberOfSections; i++) {
		PIMAGE_SECTION_HEADER pImgSectionHead = (PIMAGE_SECTION_HEADER)((DWORD_PTR)IMAGE_FIRST_SECTION(pImgNTHead) + ((DWORD_PTR)IMAGE_SIZEOF_SECTION_HEADER * i));
        char text_section[] = {'.','t','e','x','t',0};
		if (!help_strcmp_f((char *)pImgSectionHead->Name,text_section)) {
			
			void * module_text_segment = (char*) module + pImgSectionHead->VirtualAddress;
			int module_size = pImgSectionHead->Misc.VirtualSize;

            int offset = 0;
            char * gadget_return;
            char * negative;
            gadget_return = (char*) module_text_segment + find_mov_qword_ptr_req(module_text_segment,module_size,&offset,&negative);
            
            *gadget_offset = offset;
            *gadget_negative = negative;
            if(gadget_return == module_text_segment){
                // If the offset returned is zero then it means the gadget is not in the specified address range
                // We do this in case we would want to loop through others
                *gadget = NULL;
            }else{
                *gadget = gadget_return;
            }

		}
	}
}

short int find_read_gadget(rop_gadget * gadget){
    PPEB peb = NULL;

    #if defined(_WIN64)
        peb = (PPEB)__readgsqword(0x60);
    #else
        peb = (PPEB)__readfsdword(0x30);
    #endif

    PPEB_LDR_DATA ldr = peb->Ldr;
    LIST_ENTRY list = ldr->InLoadOrderModuleList;

    PLDR_DATA_TABLE_ENTRY Flink = *((PLDR_DATA_TABLE_ENTRY*)(&list));
    PLDR_DATA_TABLE_ENTRY curr_module = Flink;

    while (curr_module != NULL && curr_module->BaseAddress != NULL) {
        if (curr_module->BaseDllName.Buffer == NULL) continue;

        size_t module_address = curr_module->BaseAddress;
        rop_gadget temp_gadget;
        SecureZeroMemory(&temp_gadget, sizeof(temp_gadget));
        find_read_gadget_module(module_address,&temp_gadget.Address,&temp_gadget.Offset,&temp_gadget.Negative);

        if(temp_gadget.Address != NULL){
            gadget->Address = temp_gadget.Address;
            gadget->Offset = temp_gadget.Offset;
            gadget->Negative = temp_gadget.Negative;
            return 1;
        }

        curr_module = (PLDR_DATA_TABLE_ENTRY)curr_module->InLoadOrderModuleList.Flink;
    }
    return 0;
}

short int find_write_gadget(rop_gadget * gadget){
    PPEB peb = NULL;

    #if defined(_WIN64)
        peb = (PPEB)__readgsqword(0x60);
    #else
        peb = (PPEB)__readfsdword(0x30);
    #endif

    PPEB_LDR_DATA ldr = peb->Ldr;
    LIST_ENTRY list = ldr->InLoadOrderModuleList;

    PLDR_DATA_TABLE_ENTRY Flink = *((PLDR_DATA_TABLE_ENTRY*)(&list));
    PLDR_DATA_TABLE_ENTRY curr_module = Flink;

    while (curr_module != NULL && curr_module->BaseAddress != NULL) {
        if (curr_module->BaseDllName.Buffer == NULL) continue;

        size_t module_address = curr_module->BaseAddress;
        rop_gadget temp_gadget;
        SecureZeroMemory(&temp_gadget, sizeof(temp_gadget));
        find_write_gadget_module(module_address,&temp_gadget.Address,&temp_gadget.Offset,&temp_gadget.Negative);

        if(temp_gadget.Address != NULL){
            gadget->Address = temp_gadget.Address;
            gadget->Offset = temp_gadget.Offset;
            gadget->Negative = temp_gadget.Negative;
            return 1;
        }

        curr_module = (PLDR_DATA_TABLE_ENTRY)curr_module->InLoadOrderModuleList.Flink;
    }
    return 0;
}