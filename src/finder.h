#pragma once
#include "defs.h"
#include <windows.h>

extern void find_read_gadget_module(LPVOID module,char ** gadget, int * gadget_offset, char * gadget_negative);
extern void find_write_gadget_module(LPVOID module,char ** gadget, int * gadget_offset, char * gadget_negative);
extern short int find_read_gadget(rop_gadget * gadget);
extern short int find_write_gadget(rop_gadget * gadget);