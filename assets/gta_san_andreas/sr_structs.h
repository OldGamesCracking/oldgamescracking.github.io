/**
 * Memory layout of the VM structs used in SecuROM 7 as seen in GTA San Andreas
 */

#include <Windows.h>


#pragma pack(push,1)

/**
 * Note:    The instruction is loaded as a single DWORD, so keep endianess in mind!
 *          In a register this would look as follows: MSB -> [OperandB_Enc, OperandA_Enc, NextOpCode_Enc, NextKey] <- LSB
 */

typedef struct
{
    BYTE NextKey;
    BYTE NextOpCode_Enc;
    BYTE OperandA_Enc;
    BYTE OperandB_Enc;
} VM_INSTRUCTION_t;

#pragma pack(pop)


#pragma pack(push,4)

typedef struct
{
    void *Instructions;
} VM_PROGRAM_t;

// Created by PUSHAD, PUSHFD
typedef struct
{
    // 0x00
    DWORD EFLAGS;
    // 0x04
    DWORD EDI;
    // 0x08
    DWORD ESI;
    // 0x0C
    DWORD EBP;
    // 0x10
    DWORD ESP;
    // 0x14
    DWORD EBX;
    // 0x18
    DWORD EDX;
    // 0x1C
    DWORD ECX;
    // 0x20
    DWORD EAX;
    // 0x24
    DWORD ReturnAddress;
    // 0x28
    DWORD arg1;
    // 0x2C
    DWORD arg2;
    // ...
} VM_CONTEXT_t;

typedef struct
{
    void *HandlerOffset_Enc[0x100]; // Relative offsets to VMEnter
} VM_HANDLER_t;

typedef struct
{
    DWORD Lock;
    
    union
    {
        struct NamedData
        {
            // 0x0
            DWORD Handlers_Offset;
            // 0x4
            DWORD IP_Offset;
            // 0x8
            DWORD EFLAGS;
            // 0xC
            void *VMEnter;
            // 0x10
            BYTE RunningKey;
            // 0x14
            void *Data; // Pointer to own struct
            // 0x18
            VM_PROGRAM_t *Program;
            // 0x1C
            VM_CONTEXT_t *Context;
            // 0x20
            VM_HANDLER_t *Handlers;
        };
        
        DWORD Raw[0x100];
    } Data;
} VM_t;

/**
 * Layout for the encrypted functions
 */

typedef struct
{
    // 0x00
    BYTE StolenBytes_Enc[8];
    // 0x08
    SIZE_T DataLen_Enc;
    // 0x0C
    BYTE Unused1[4];
    // 0x10
    DWORD DataKey_Enc;
    // 0x14
    BYTE Unused2[0x1C];
    // 0x30
    DWORD ReturnAddress_Enc;
} FunctionData_t;

typedef struct
{
    DWORD NumFunctions;
    FunctionData_t Func[500];
} EncryptedFunctions_t;

/**
 * Node for the "Recursive VM"
 */

typedef struct rvm_node
{
    BOOL LeftIsConst : 1;
    BOOL RightIsConst : 1;
    DWORD Instruction : 29;
    BOOL Unknown : 1;
    union
    {
        rvm_node *Child;
        DWORD Value;
    } Left;
    union
    {
        rvm_node *Child;
        DWORD Value;
    } Right;
} RVM_NODE_t;


#pragma pack(pop)
