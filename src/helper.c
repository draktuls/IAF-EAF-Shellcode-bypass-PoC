#include "helper.h"
#include "rop.h"
#ifdef DEBUG_D
    #include <stdio.h>
#endif

#ifdef DEBUG_D
void printBytes(void* ptr,int size){
	unsigned char* p = (unsigned char*)ptr;
	printf("Bytes: ");
	for(int i =0;i<size;i++){
		printf("%02hhx",p[i]);
	}
	puts("");
}
#endif

int help_memcmp (const void *str1, const void *str2, size_t count)
{
  register const unsigned char *s1 = (const unsigned char*)str1;
  register const unsigned char *s2 = (const unsigned char*)str2;

  while (count-- > 0)
    {
      if (*s1++ != *s2++)
	  return s1[-1] < s2[-1] ? -1 : 1;
    }
  return 0;
}

int help_strcmp_f(const char *target, const char *source) 
{
    int i;

    for (i = 0; source[i] == target[i]; i++)
        if (source[i] == '\0')
            return 0;
    return source[i] - target[i];
}

// String compare with gadgets
int help_strcmp(const char *target, const char *source, char* gadget, int offset, char negative) 
{
    int i;

    for (i = 0; source[i] == read_primitive_char(gadget, (char* )target + i, offset, negative); i++)
        if (source[i] == '\0')
            return 0;
    return source[i] - read_primitive_char(gadget, (char* )target + i, offset, negative);
}