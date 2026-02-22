#pragma once

#include <Windows.h>
#include <Zydis.h>
#include <vector>
#include "ProcessHelper.h"


#define PCODE_DESCRIPTORS_LOCATION  (0x667a9484)
#define PCODE_DESCRIPTORS_LEN       (0x80)
#define KEY_LOOKUP_PCODE            (0x87cec3ef)

#define NANOMITE_STATUS_VM          (0x20)


struct Transformer {
    BYTE field0_0x0;
    BYTE field1_0x1;
    BYTE field2_0x2;
    BYTE field3_0x3;
    BYTE field4_0x4;
    BYTE field5_0x5;
    BYTE field6_0x6;
    BYTE field7_0x7;
    BYTE field8_0x8;
    BYTE field9_0x9;
    BYTE field10_0xa;
    BYTE field11_0xb;
    DWORD(*transform)(struct Transformer *, DWORD);
};

struct SimpleValue_VT {
    DWORD(*get)(struct SimpleValue *, DWORD, DWORD, DWORD);
    void (*set)(struct SimpleValue *, DWORD);
};

struct SimpleValue {
    SimpleValue_VT *vt;
    DWORD value;
};

struct ValueContainer {
    struct ValueContainer *base;
    void *some_ptr;
    struct SimpleValue value;
    struct OperationHelper *op_helper;
    struct Transformer *transformer;
};

struct OperationHelper {
    void (*init)(struct OperationHelper *, struct ValueContainer *, DWORD *);
    struct ValueContainer a;
    struct ValueContainer b;
};

struct PCodeDescriptor {
    DWORD some_val;
    DWORD target_index;
    BYTE some_bool_1;
    BYTE some_bool_0;
    BYTE field4_0xa;
    BYTE field5_0xb;
    BYTE field6_0xc;
    BYTE field7_0xd;
    BYTE field8_0xe;
    BYTE field9_0xf;
    BYTE field10_0x10;
    BYTE field11_0x11;
    BYTE field12_0x12;
    BYTE field13_0x13;
    BYTE field14_0x14;
    BYTE field15_0x15;
    BYTE field16_0x16;
    BYTE field17_0x17;
    BYTE field18_0x18;
    BYTE field19_0x19;
    BYTE field20_0x1a;
    BYTE field21_0x1b;
    struct ValueContainer value;
    BYTE field23_0x34;
    BYTE field24_0x35;
    BYTE field25_0x36;
    BYTE field26_0x37;
    BYTE field27_0x38;
    BYTE field28_0x39;
    BYTE field29_0x3a;
    BYTE field30_0x3b;
    BYTE field31_0x3c;
    BYTE field32_0x3d;
    BYTE field33_0x3e;
    BYTE field34_0x3f;
    BYTE field35_0x40;
    BYTE field36_0x41;
    BYTE field37_0x42;
    BYTE field38_0x43;
    BYTE field39_0x44;
    BYTE field40_0x45;
    BYTE field41_0x46;
    BYTE field42_0x47;
    BYTE field43_0x48;
    BYTE field44_0x49;
    BYTE field45_0x4a;
    BYTE field46_0x4b;
    BYTE field47_0x4c;
    BYTE field48_0x4d;
    BYTE field49_0x4e;
    BYTE field50_0x4f;
    BYTE field51_0x50;
    BYTE field52_0x51;
    BYTE field53_0x52;
    BYTE field54_0x53;
    BYTE field55_0x54;
    BYTE field56_0x55;
    BYTE field57_0x56;
    BYTE field58_0x57;
    BYTE field59_0x58;
    BYTE field60_0x59;
    BYTE field61_0x5a;
    BYTE field62_0x5b;
    BYTE field63_0x5c;
    BYTE field64_0x5d;
    BYTE field65_0x5e;
    BYTE field66_0x5f;
    BYTE field67_0x60;
    BYTE field68_0x61;
    BYTE field69_0x62;
    BYTE field70_0x63;
    BYTE field71_0x64;
    BYTE field72_0x65;
    BYTE field73_0x66;
    BYTE field74_0x67;
    BYTE field75_0x68;
    BYTE field76_0x69;
    BYTE field77_0x6a;
    BYTE field78_0x6b;
    BYTE field79_0x6c;
    BYTE field80_0x6d;
    BYTE field81_0x6e;
    BYTE field82_0x6f;
    BYTE field83_0x70;
    BYTE field84_0x71;
    BYTE field85_0x72;
    BYTE field86_0x73;
    BYTE field87_0x74;
    BYTE field88_0x75;
    BYTE field89_0x76;
    BYTE field90_0x77;
    BYTE field91_0x78;
    BYTE field92_0x79;
    BYTE field93_0x7a;
    BYTE field94_0x7b;
    BYTE field95_0x7c;
    BYTE field96_0x7d;
    BYTE field97_0x7e;
    BYTE field98_0x7f;
    BYTE field99_0x80;
    BYTE field100_0x81;
    BYTE field101_0x82;
    BYTE field102_0x83;
    BYTE field103_0x84;
    BYTE field104_0x85;
    BYTE field105_0x86;
    BYTE field106_0x87;
    BYTE field107_0x88;
    BYTE field108_0x89;
    BYTE field109_0x8a;
    BYTE field110_0x8b;
    BYTE field111_0x8c;
    BYTE field112_0x8d;
    BYTE field113_0x8e;
    BYTE field114_0x8f;
    BYTE field115_0x90;
    BYTE field116_0x91;
    BYTE field117_0x92;
    BYTE field118_0x93;
    BYTE field119_0x94;
    BYTE field120_0x95;
    BYTE field121_0x96;
    BYTE field122_0x97;
    BYTE field123_0x98;
    BYTE field124_0x99;
    BYTE field125_0x9a;
    BYTE field126_0x9b;
    BYTE field127_0x9c;
    BYTE field128_0x9d;
    BYTE field129_0x9e;
    BYTE field130_0x9f;
    BYTE field131_0xa0;
    BYTE field132_0xa1;
    BYTE field133_0xa2;
    BYTE field134_0xa3;
    BYTE field135_0xa4;
    BYTE field136_0xa5;
    BYTE field137_0xa6;
    BYTE field138_0xa7;
    BYTE field139_0xa8;
    BYTE field140_0xa9;
    BYTE field141_0xaa;
    BYTE field142_0xab;
    BYTE field143_0xac;
    BYTE field144_0xad;
    BYTE field145_0xae;
    BYTE field146_0xaf;
    BYTE field147_0xb0;
    BYTE field148_0xb1;
    BYTE field149_0xb2;
    BYTE field150_0xb3;
    BYTE field151_0xb4;
    BYTE field152_0xb5;
    BYTE field153_0xb6;
    BYTE field154_0xb7;
    BYTE field155_0xb8;
    BYTE field156_0xb9;
    BYTE field157_0xba;
    BYTE field158_0xbb;
    BYTE field159_0xbc;
    BYTE field160_0xbd;
    BYTE field161_0xbe;
    BYTE field162_0xbf;
    BYTE field163_0xc0;
    BYTE field164_0xc1;
    BYTE field165_0xc2;
    BYTE field166_0xc3;
    DWORD len_enc; /* Created by retype action */
    BYTE field168_0xc8;
    BYTE field169_0xc9;
    BYTE field170_0xca;
    BYTE field171_0xcb;
    BYTE field172_0xcc;
    BYTE field173_0xcd;
    BYTE opcode[16];
    BYTE field175_0xde;
    BYTE field176_0xdf;
    BYTE field177_0xe0;
    BYTE field178_0xe1;
    BYTE field179_0xe2;
    BYTE field180_0xe3;
    BYTE field181_0xe4;
    BYTE field182_0xe5;
    BYTE field183_0xe6;
    BYTE field184_0xe7;
    BYTE field185_0xe8;
    BYTE field186_0xe9;
    BYTE field187_0xea;
    BYTE field188_0xeb;
    BYTE field189_0xec;
    BYTE field190_0xed;
    BYTE field191_0xee;
    BYTE field192_0xef;
    BYTE field193_0xf0;
    BYTE field194_0xf1;
    BYTE field195_0xf2;
    BYTE field196_0xf3;
    BYTE field197_0xf4;
    BYTE field198_0xf5;
    BYTE field199_0xf6;
    BYTE field200_0xf7;
    DWORD code_type; /* len / type ? */
};

#pragma pack(push,1)
struct NanomiteData
{
    BYTE size;
    union STATUS_OFFSET
    {
        BYTE status;
        BYTE offset;
    } so;
    BYTE unknown0;
    union DATA_IV
    {
        BYTE data[8];
        struct IV
        {
            DWORD IV1;
            DWORD IV2;
        } iv;
    } di;
    BYTE unknown1;
    DWORD checksum;
};
#pragma pack(pop)

struct VM_IV
{
    DWORD Key;
    DWORD IV1;
    DWORD IV2;
};

struct PCodeDescriptorsContainer {
    DWORD u0;
    DWORD u1;
    WORD valid[PCODE_DESCRIPTORS_LEN];
    struct PCodeDescriptor codes[PCODE_DESCRIPTORS_LEN];
};


class SafeDiscHelper
{
private:
    DWORD DecryptVMLookupFromPCode(DWORD Lookup);
    DWORD GetVMLookupFromPCode(const PCodeDescriptor *const Descriptor);

    HANDLE hProcess;
    ProcessHelper *process;

public:
    SafeDiscHelper(HANDLE hProcess);
    ~SafeDiscHelper();

    bool IsVMEntry(ZyanU64 address);
    bool IsRemoteProcStub(ZyanU64 address);
    bool IsJumpPadSetup(ZyanU64 address);

    DWORD GetVMLookup(DWORD ReturnAddress, DWORD ImageBase);
    bool GetPCodeDescriptor(DWORD Lookup, PCodeDescriptor *const PCode);
    void VM_Populate_Operand(BYTE Operand, ZydisEncoderOperand *const operand, DWORD imm);
    DWORD VM_Transform_Key(DWORD value);
    void VM_Devirtualize(VM_IV *iv, ZyanU8 *out_instruction, ZyanUSize *out_len, bool branchShort = false);
};