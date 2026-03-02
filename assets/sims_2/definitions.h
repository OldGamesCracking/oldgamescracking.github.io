#include <Windows.h>

struct JUMPBACK_t {
    struct STACK_CONTEXT_t *frame;
    DWORD ret_addr;
    DWORD r2;
    DWORD esp_org;
    DWORD image_base;
    DWORD r5;
    DWORD eflags;
    DWORD r7;
    BYTE jumpback[16];
};

struct STACK_CONTEXT_t {
    DWORD edi;
    DWORD esi;
    DWORD ebp;
    DWORD esp;
    DWORD ebx;
    DWORD edx;
    DWORD ecx;
    DWORD eax;
    DWORD eflags;
    DWORD esp_org;
    DWORD image_base;
    DWORD ret_addr;
};