#if defined(_WIN64)

extern long long read_primitive_long_long(
    char* gadget,
    char* target,
    int offset,
    char negative
);

#else

extern int get_current_eip();

#endif

extern int read_primitive_int(
    char* gadget,
    char* target,
    int offset,
    char negative
);

extern char read_primitive_char(
    char* gadget,
    char* target,
    int offset,
    char negative
);

extern char write_primitive(
    char* gadget,
    char* target,
    char* new_pointer
);
