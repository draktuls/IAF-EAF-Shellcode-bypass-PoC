#pragma once
#include <windows.h>


extern int help_memcmp (const void *str1, const void *str2, size_t count);
extern int help_strcmp_f(const char *target, const char *source);
extern int help_strcmp(const char *target, const char *source, char* gadget, int offset, char negative);
#ifdef DEBUG_D
extern void printBytes(void* ptr,int size);
#endif