#include "SafeDiscHelper.h"
#include "md5.h"
#include "Logging.h"


#define OPERAND_REG_EAX		(0x0)
#define OPERAND_REG_EBX		(0x1)
#define OPERAND_REG_ECX		(0x2)
#define OPERAND_REG_EDX		(0x3)
#define OPERAND_REG_ESP		(0x4)
#define OPERAND_REG_EBP		(0x5)
#define OPERAND_REG_ESI		(0x6)
#define OPERAND_REG_EDI		(0x7)
#define OPERAND_REG_IMM		(0x8)
#define OPERAND_REG_EFLAGS	(0x9)
#define OPERAND_REG_EIP		(0xA)


SafeDiscHelper::SafeDiscHelper(HANDLE hProcess) : 
	hProcess(hProcess)
{
	process = new ProcessHelper(hProcess);
}

SafeDiscHelper::~SafeDiscHelper()
{
	if (process == nullptr)
	{
		return;
	}

	delete process;

	process = nullptr;
}

bool SafeDiscHelper::IsVMEntry(ZyanU64 address)
{
	/* Check Setup */
	std::vector <ZydisMnemonic> expectedInstructionsSetup = {
		ZYDIS_MNEMONIC_PUSH,
		ZYDIS_MNEMONIC_PUSH,
		ZYDIS_MNEMONIC_CALL
	};

	ZyanU64 lastAt;

	if (!process->IsInstructions(address, expectedInstructionsSetup, &lastAt))
	{
		return false;
	}

	ZyanU64 callTo;

	if (!process->GetDestination(lastAt, &callTo))
	{
		return false;
	}

	std::vector <ZydisMnemonic> expectedInstructionsJmp = {
		ZYDIS_MNEMONIC_MOV,
		ZYDIS_MNEMONIC_POP,
		ZYDIS_MNEMONIC_LEA,
		ZYDIS_MNEMONIC_MOV,
		ZYDIS_MNEMONIC_JMP
	};

	return process->IsInstructions(callTo, expectedInstructionsJmp);
}

bool SafeDiscHelper::IsRemoteProcStub(ZyanU64 address)
{
	std::vector <ZydisMnemonic> expectedInstructions = {
		ZYDIS_MNEMONIC_PUSH,
		ZYDIS_MNEMONIC_PUSHFD,
		ZYDIS_MNEMONIC_PUSHAD
	};

	return process->IsInstructions(address, expectedInstructions);
}

bool SafeDiscHelper::IsJumpPadSetup(ZyanU64 address)
{
	/* Check Setup */
	std::vector <ZydisMnemonic> expectedInstructionsSetup1 = {
		ZYDIS_MNEMONIC_PUSH,
		ZYDIS_MNEMONIC_CALL
	};

	if (process->IsInstructions(address, expectedInstructionsSetup1))
	{
		/* Version 1 */
		return true;
	}

	std::vector <ZydisMnemonic> expectedInstructionsSetup2 = {
		ZYDIS_MNEMONIC_PUSH,
		ZYDIS_MNEMONIC_JMP
	};

	if (process->IsInstructions(address, expectedInstructionsSetup2))
	{
		/* Version 1 */
		return true;
	}

	return false;
}

DWORD SafeDiscHelper::GetVMLookup(DWORD ReturnAddress, DWORD ImageBase)
{
	DWORD rva = ReturnAddress - ImageBase;

	MD5Context ctx;

	md5Init(&ctx);

	md5Update(&ctx, (uint8_t*)&rva, sizeof(DWORD));

	md5Finalize(&ctx);

	return *(DWORD*)&ctx.digest[0];
}

DWORD SafeDiscHelper::DecryptVMLookupFromPCode(DWORD Lookup)
{
	return Lookup ^ KEY_LOOKUP_PCODE;
}

DWORD SafeDiscHelper::GetVMLookupFromPCode(const PCodeDescriptor *const Descriptor)
{
	return DecryptVMLookupFromPCode(Descriptor->lookup.value.value);
}

bool SafeDiscHelper::GetPCodeDescriptor(DWORD Lookup, PCodeDescriptor *const PCode)
{
	const PCodeDescriptorsContainer *PCODE_DESCRIPTORS;

	if (!process->ReadMemory((LPVOID)PCODE_DESCRIPTORS_LOCATION, (PBYTE)&PCODE_DESCRIPTORS, sizeof(PCodeDescriptorsContainer*)))
	{
		Log.Error("Could not read descriptors");

		return false;
	}
	
	for (auto i = 0; i < PCODE_DESCRIPTORS_LEN; i++)
	{
		auto idx = (i + Lookup) % PCODE_DESCRIPTORS_LEN;

		const PCodeDescriptor *PCodeAddress = &PCODE_DESCRIPTORS->codes[idx];

		if (!process->ReadMemory((LPVOID)PCodeAddress, (PBYTE)PCode, sizeof(PCodeDescriptor)))
		{
			Log.Error("Could not read PCode");

			return false;
		}

		WORD Valid;

		const WORD *ValidAddress = &PCODE_DESCRIPTORS->valid[idx];

		if (!process->ReadMemory((LPVOID)ValidAddress, (PBYTE)&Valid, sizeof(WORD)))
		{
			Log.Error("Could not read Valid");

			return false;
		}
		
		if ((Valid != 0) && (GetVMLookupFromPCode(PCode) == Lookup))
		{
			return true;
		}
	}

	return false;
}

void SafeDiscHelper::VM_Populate_Operand(BYTE Operand, ZydisEncoderOperand *const operand, DWORD imm)
{
	operand->type = ZYDIS_OPERAND_TYPE_REGISTER;

	switch (Operand)
	{
		case (OPERAND_REG_EAX):
		{
			operand->reg.value = ZYDIS_REGISTER_EAX;

			break;
		}

		case (OPERAND_REG_EBX):
		{
			operand->reg.value = ZYDIS_REGISTER_EBX;

			break;
		}

		case (OPERAND_REG_ECX):
		{
			operand->reg.value = ZYDIS_REGISTER_ECX;

			break;
		}

		case (OPERAND_REG_EDX):
		{
			operand->reg.value = ZYDIS_REGISTER_EDX;

			break;
		}

		case (OPERAND_REG_ESP):
		{
			operand->reg.value = ZYDIS_REGISTER_ESP;

			break;
		}

		case (OPERAND_REG_EBP):
		{
			operand->reg.value = ZYDIS_REGISTER_EBP;

			break;
		}

		case (OPERAND_REG_ESI):
		{
			operand->reg.value = ZYDIS_REGISTER_ESI;

			break;
		}

		case (OPERAND_REG_EDI):
		{
			operand->reg.value = ZYDIS_REGISTER_EDI;

			break;
		}

		case (OPERAND_REG_IMM):
		{
			/* Special 'register' */
			operand->type = ZYDIS_OPERAND_TYPE_IMMEDIATE;

			operand->imm.s = (int32_t)imm;

			break;
		}

		case (OPERAND_REG_EFLAGS):
		{
			operand->reg.value = ZYDIS_REGISTER_EFLAGS;

			break;
		}

		case (OPERAND_REG_EIP):
		{
			operand->reg.value = ZYDIS_REGISTER_EIP;

			break;
		}

		default:
		{
			Log.Error("Invalid Operand");

			break;
		}
	}

}

DWORD SafeDiscHelper::VM_Transform_Key(DWORD value)
{
	DWORD r6F = 0xF0F0F0F0;
	DWORD r70 = 0x0F0F0F0F;
	DWORD r71 = 0xFFFFFFFF;

	DWORD r6C = value & r6F;
	DWORD r72 = (value ^ r71) & r70;
	r6C |= r72;
	r72 = ((r6C << 15) ^ r71) & 0xffffffff;
	r6C = (r6C + r72) & 0xffffffff;
	r72 = (r6C >> 10);
	r6C ^= r72;
	r72 = ((r6C << 3) ^ r71) & 0xffffffff;
	r6C = (r6C + r72) & 0xffffffff;
	r72 = (r6C >> 6);
	r6C ^= r72;
	r72 = ((r6C << 11) ^ r71) & 0xffffffff;
	r6C = (r6C + r72) & 0xffffffff;
	r72 = (r6C >> 16);
	r6C ^= r72;

	r6C &= 0xffffffff;

	return r6C;
}

void SafeDiscHelper::VM_Devirtualize(VM_IV *iv, ZyanU8 *out_instruction, ZyanUSize *out_len, bool branchShort)
{
	ZydisEncoderRequest req;
	memset(&req, 0, sizeof(req));

	req.machine_mode = ZYDIS_MACHINE_MODE_LEGACY_32;
	req.allowed_encodings = ZYDIS_ENCODABLE_ENCODING_LEGACY;
	
	DWORD Key_IV2 = VM_Transform_Key(VM_Transform_Key(iv->Key));
	DWORD IV2 = iv->IV2 ^ Key_IV2;

	BYTE Opcode = (IV2 >> 16) & 0xff;
	BYTE OperandA = (IV2 >> 8) & 0xff;
	BYTE OperandB = (IV2 >> 0) & 0xff;

	Log.Debug("Opcode: %02X", Opcode);
	Log.Debug("OperandA: %02X", OperandA);
	Log.Debug("OperandB: %02X", OperandB);

	DWORD Key_IV1 = VM_Transform_Key(Key_IV2);
	DWORD IV1 = iv->IV1 ^ Key_IV1;

	Log.Debug("IV1: %08X", IV1);

	if (Opcode == 0x0000)
	{
		if (OperandA == OPERAND_REG_EIP)
		{
			req.mnemonic = ZYDIS_MNEMONIC_JMP;
			req.branch_type = ZYDIS_BRANCH_TYPE_FAR;
			req.operand_count = 1;

			VM_Populate_Operand(OperandB, &req.operands[0], IV1);
		}
		else
		{
			req.mnemonic = ZYDIS_MNEMONIC_MOV;
			req.operand_count = 2;

			VM_Populate_Operand(OperandA, &req.operands[0], IV1);
			VM_Populate_Operand(OperandB, &req.operands[1], IV1);
		}
	}
	else if ((0x0001 <= Opcode) && (Opcode <= 0x000C))
	{
		if (branchShort)
		{
			req.branch_type = ZYDIS_BRANCH_TYPE_SHORT;
			req.branch_width = ZYDIS_BRANCH_WIDTH_8;
		}
		else
		{
			req.branch_type = ZYDIS_BRANCH_TYPE_NEAR;
			req.branch_width = ZYDIS_BRANCH_WIDTH_32;
		}

		if (OperandA != OPERAND_REG_EIP)
		{
			Log.Error("Strange OperandA");

			*out_len = 0;

			return;
		}

		if (OperandB != OPERAND_REG_IMM)
		{
			Log.Error("Strange OperandB");

			*out_len = 0;

			return;
		}

		req.operand_count = 1;

		req.operands[0].type = ZYDIS_OPERAND_TYPE_IMMEDIATE;
		req.operands[0].imm.s = (ZyanI32)IV1;
		
		switch (Opcode)
		{
			case (0x0001):
			{
				req.mnemonic = ZYDIS_MNEMONIC_JMP;

				break;
			}

			case (0x0002):
			{
				req.mnemonic = ZYDIS_MNEMONIC_CALL;

				break;
			}

			case (0x0003):
			{
				req.mnemonic = ZYDIS_MNEMONIC_JZ;

				break;
			}

			case (0x0004):
			{
				req.mnemonic = ZYDIS_MNEMONIC_JNZ;

				break;
			}

			case (0x0005):
			{
				req.mnemonic = ZYDIS_MNEMONIC_JB;

				break;
			}

			case (0x0006):
			{
				req.mnemonic = ZYDIS_MNEMONIC_JNB;

				break;
			}

			case (0x0007):
			{
				req.mnemonic = ZYDIS_MNEMONIC_JO;

				break;
			}

			case (0x0008):
			{
				req.mnemonic = ZYDIS_MNEMONIC_JNO;

				break;
			}

			case (0x0009):
			{
				req.mnemonic = ZYDIS_MNEMONIC_JP;

				break;
			}

			case (0x000A):
			{
				req.mnemonic = ZYDIS_MNEMONIC_JNP;

				break;
			}

			case (0x000B):
			{
				req.mnemonic = ZYDIS_MNEMONIC_JS;

				break;
			}

			case (0x000C):
			{
				req.mnemonic = ZYDIS_MNEMONIC_JNS;

				break;
			}
		}
	}
	else if (Opcode <= 0x00013)
	{
		req.operand_count = 2;

		VM_Populate_Operand(OperandA, &req.operands[0], IV1);
		VM_Populate_Operand(OperandB, &req.operands[1], IV1);

		switch (Opcode)
		{
			case (0x000D):
			{
				req.mnemonic = ZYDIS_MNEMONIC_TEST;

				break;
			}

			case (0x000E):
			{
				req.mnemonic = ZYDIS_MNEMONIC_AND;

				break;
			}

			case (0x000F):
			{
				req.mnemonic = ZYDIS_MNEMONIC_XOR;

				break;
			}

			case (0x0010):
			{
				req.mnemonic = ZYDIS_MNEMONIC_OR;

				break;
			}

			case (0x0011):
			{
				req.mnemonic = ZYDIS_MNEMONIC_CMP;

				break;
			}

			case (0x0012):
			{
				req.mnemonic = ZYDIS_MNEMONIC_SUB;

				break;
			}

			case (0x0013):
			{
				req.mnemonic = ZYDIS_MNEMONIC_ADD;

				break;
			}
		}
	}
	else
	{
		Log.Error("Unknown Opcode");

		*out_len = 0;

		return;
	}

	ZyanStatus status = ZydisEncoderEncodeInstruction(&req, out_instruction, out_len);

	Log.Debug("Encoder status: %08X", status);

	if (ZYAN_FAILED(status))
	{
		*out_len = 0;
	}
}