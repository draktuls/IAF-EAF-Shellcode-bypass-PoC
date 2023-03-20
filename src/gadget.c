#pragma once
#include <windows.h>
#include "gadget.h"

#if defined(_WIN64)
int find_mov_req_qword_ptr(char * pMem, int size, int * ptr_offset, char * negative){
	
	int i = 0;
	int offset = 0;
    int max_gadget = 8; // 48:8B80 A8160000 + c3
    BYTE mov_rax_qword_ptr[] = {'\x48','\x8b'};
    int mov_size = sizeof(mov_rax_qword_ptr);

    // 00007FF904638FD5 | 48:8B00 | mov rax,qword ptr ds:[rax]
    // 00007FF9046B2FB7 | 48:8B40 38 | mov rax,qword ptr ds:[rax+38]
    // 00007FF904687FF9 | 48:8B80 A8160000 | mov rax,qword ptr ds:[rax+16A8]


    /*
    0x00000001800d7ff9 : mov rax, qword ptr [rax + 0x16a8] ; ret
    0x0000000180070889 : mov rax, qword ptr [rax + 0x17b8] ; ret
    0x0000000180088029 : mov rax, qword ptr [rax + 0x17c0] ; ret
    0x0000000180102fb7 : mov rax, qword ptr [rax + 0x38] ; ret
    0x0000000180002d39 : mov rax, qword ptr [rax + 0x60] ; ret
    0x0000000180088fd5 : mov rax, qword ptr [rax] ; ret
    */

    // Look for 48 8b, size - max_gadget to not cause access violation
	for (i = 0; i < size - max_gadget; i++) {
		if (!help_memcmp(pMem + i, mov_rax_qword_ptr, mov_size)) {

            char * gadget_memory = (pMem + i);
            
            // Now decide if it's the right gadget based on the third mov argument and ret opcode with cc after it
            // (There is probably a better way)

            short int first_bool = gadget_memory[2] == '\x00' && gadget_memory[3] == '\xc3' && gadget_memory[4] == '\xcc';

            short int second_bool = gadget_memory[2] == '\x40' && gadget_memory[4] == '\xc3' && gadget_memory[5] == '\xcc';

            short int third_bool = gadget_memory[2] == '\x80' && gadget_memory[7] == '\xc3' && gadget_memory[8] == '\xcc';

            if (first_bool || second_bool || third_bool) {

                // We have one of the gadgets and now we need to figure out the outputs based on the third mov argument
                // There could be any registers or qword pointer to different registers

                int convert = 0;
                char * convert_ptr = &convert;
                switch(gadget_memory[2]){
                    case '\x00':

                        // Basic gadget doesn't have any offset to the pointer
                        // And the signess doesn't really matter

                        *ptr_offset = 0;
                        offset = i;
                        *negative = 0;

                        break;

                    case '\x40':

                        // We have a char size integer here
                        // There can also be a negative value
                        // There is definitely a better solution to this
                        // But we just check if it's lower and if so set negative bool to yes
                        // And abs() the convert value as char
                        
                        convert_ptr[0] = gadget_memory[3];
                        *ptr_offset = convert;
                        offset = i;

                        if((char)gadget_memory[3] < 0){
                            *negative = 1;
                            convert_ptr[0] = gadget_memory[3] * -1;
                            *ptr_offset = convert;
                        }else{
                            *negative = 0;
                        }
                        break;

                    case '\x80':

                        // Here we have normal dword/int offset
                        // Use dummy int and byte by byte load it
                        // And check negative as before

                        convert_ptr[3] = gadget_memory[6];
                        convert_ptr[2] = gadget_memory[5];
                        convert_ptr[1] = gadget_memory[4];
                        convert_ptr[0] = gadget_memory[3];

                        *ptr_offset = convert;
                        offset = i;
                        if(convert < 0){ 
                            *negative = 1;
                            *ptr_offset = convert * -1;
                        }else{
                            *negative = 0;
                        }

                        break;

                    default:

                        // Invalid mov instruction
                        continue;
                }
                // We are done
                break;
            }

            // Well the thing is not a gadget so move on
            continue;
		}
	}

	return offset;
}

int find_mov_qword_ptr_req(char * pMem, int size, int * ptr_offset, char * negative){
	
	int i = 0;
	int offset = 0;
    BYTE mov_qword_ptr_rax[] = {'\x48','\x89','\x01','\xC3'};
    int mov_size = sizeof(mov_qword_ptr_rax);
    int max_gadget = mov_size;

    // 00007FF9020AD358 | 48:8901 | mov qword ptr ds:[rcx],rax

    /*
    0x000000018008d358 : mov qword ptr [rcx], rax ; ret
    0x000000018013d8b5 : mov qword ptr [rcx], rcx ; ret
    0x000000018013d96a : mov qword ptr [r8], rdx ; ret
    0x0000000180007af5 : mov qword ptr [r8], rcx ; ret
    */

    // Look for 48 89, size - max_gadget to not cause access violation
	for (i = 0; i < size - max_gadget; i++) {
		if (!help_memcmp(pMem + i, mov_qword_ptr_rax, mov_size)) {
            offset = i;
            *ptr_offset = 0;
            *negative = 0;
        }
	}

	return offset;
}

#else

int find_mov_req_qword_ptr(char * pMem, int size, int * ptr_offset, char * negative){
	
	int i = 0;
	int offset = 0;
    int max_gadget = 7; // 8b80b0160000c3
    BYTE mov[] = {'\x8b'};
    int mov_size = sizeof(mov);


    /*
    0x4b31ff86 : mov eax, dword ptr [eax + 0x14] ; ret // 8b4014c3
    0x4b333e19 : mov eax, dword ptr [eax + 0x16b0] ; ret // 8b80b0160000c3
    0x4b2cebfe : mov eax, dword ptr [eax] ; ret // 8b00c3
    */

    // Look for 8b, size - max_gadget to not cause access violation
	for (i = 0; i < size - max_gadget; i++) {
		if (!help_memcmp(pMem + i, mov, mov_size)) {

            char * gadget_memory = (pMem + i);

            short int first_bool = gadget_memory[1] == '\x00' && gadget_memory[2] == '\xc3' && gadget_memory[3] == '\xcc';

            short int second_bool = gadget_memory[1] == '\x40' && gadget_memory[3] == '\xc3' && gadget_memory[4] == '\xcc';

            short int third_bool = gadget_memory[1] == '\x80' && gadget_memory[6] == '\xc3' && gadget_memory[7] == '\xcc';

            if (first_bool || second_bool || third_bool) {

                int convert = 0;
                char * convert_ptr = &convert;
                switch(gadget_memory[1]){
                    case '\x00':

                        // Basic gadget doesn't have any offset to the pointer
                        // And the signess doesn't really matter

                        *ptr_offset = 0;
                        offset = i;
                        *negative = 0;

                        break;

                    case '\x40':

                        // We have a char size integer here
                        // There can also be a negative value
                        // There is definitely a better solution to this
                        // But we just check if it's lower and if so set negative bool to yes
                        // And abs() the convert value as char
                        
                        convert_ptr[0] = gadget_memory[2];
                        *ptr_offset = convert;
                        offset = i;

                        if((char)gadget_memory[2] < 0){
                            *negative = 1;
                            convert_ptr[0] = gadget_memory[2] * -1;
                            *ptr_offset = convert;
                        }else{
                            *negative = 0;
                        }
                        break;

                    case '\x80':

                        // Here we have normal dword/int offset
                        // Use dummy int and byte by byte load it
                        // And check negative as before

                        convert_ptr[3] = gadget_memory[5];
                        convert_ptr[2] = gadget_memory[4];
                        convert_ptr[1] = gadget_memory[3];
                        convert_ptr[0] = gadget_memory[2];

                        *ptr_offset = convert;
                        offset = i;
                        if(convert < 0){ 
                            *negative = 1;
                            *ptr_offset = convert * -1;
                        }else{
                            *negative = 0;
                        }

                        break;

                    default:

                        // Invalid mov instruction
                        continue;
                }
                // We are done
                break;
            }

            // Well the thing is not a gadget so move on
            continue;
		}
	}

	return offset;
}

int find_mov_qword_ptr_req(char * pMem, int size, int * ptr_offset, char * negative){
	
	int i = 0;
	int offset = 0;
    BYTE mov_dword_ptr_rax[] = {'\x89','\x01','\xC3'};
    int mov_size = sizeof(mov_dword_ptr_rax);
    int max_gadget = mov_size;

    /*
    0x4b33492f : mov dword ptr [ecx], eax ; ret // 8901c3
    */

    // Look for 89 01, size - max_gadget to not cause access violation
	for (i = 0; i < size - max_gadget; i++) {
		if (!help_memcmp(pMem + i, mov_dword_ptr_rax, mov_size)) {
            offset = i;
            *ptr_offset = 0;
            *negative = 0;
        }
	}

	return offset;
}

#endif