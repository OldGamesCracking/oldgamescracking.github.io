#pragma once

#include <cinttypes>
#include <deque>
#include <Zydis.h>
#include <set>
#include <unordered_set>


class CodeExplorer
{
    public:
        enum CodeStatus : uint8_t
        {
            STATUS_EXPLORED = (1 << 0),
            STATUS_START_OF_INSTRUCTION = (1 << 1),
            STATUS_IGNORED = (1 << 2),
            STATUS_FILLING = (1 << 3),
            STATUS_FOUND_IN_IMMEDIATE = (1 << 4),
            STATUS_START_OF_FUNCTION = (1 << 5),
            STATUS_IS_RETURN = (1 << 6)
        };

        enum class ExplorerResult
        {
            DoneExploring,
            JumpOutOfTextSection,
            IndirectBranchFromMemory,
            CallInterSection,
            UnusualCode,
            InvalidCode,
            UnusualCodeInSlideDown,
            InvalidCodeInSlideDown,
            IATCallByRegister
        };

        struct ResultData
        {
            ZyanU64 ResultAddress;
            ZyanU64 TargetAddress;

            ZydisDisassembledInstruction Instruction;
        };

    private:
        
        enum BranchType : uint32_t
        {
            // Basic types.
            BTRet = 1 << 0,
            BTCall = 1 << 1,
            BTFarCall = 1 << 2,
            BTFarRet = 1 << 3,
            BTSyscall = 1 << 4, // Also sysenter
            BTSysret = 1 << 5, // Also sysexit
            BTInt = 1 << 6,
            BTInt3 = 1 << 7,
            BTInt1 = 1 << 8,
            BTIret = 1 << 9,
            BTCondJmp = 1 << 10,
            BTUncondJmp = 1 << 11,
            BTFarJmp = 1 << 12,
            BTXbegin = 1 << 13,
            BTXabort = 1 << 14,
            BTRsm = 1 << 15,
            BTLoop = 1 << 16,

            BTJmp = BTCondJmp | BTUncondJmp,

            // Semantic groups (behaves like XX).
            BTCallSem = BTCall | BTFarCall | BTSyscall | BTInt,
            BTRetSem = BTRet | BTSysret | BTIret | BTFarRet | BTRsm,
            BTCondJmpSem = BTCondJmp | BTLoop | BTXbegin,
            BTUncondJmpSem = BTUncondJmp | BTFarJmp | BTXabort,

            BTRtm = BTXabort | BTXbegin,
            BTFar = BTFarCall | BTFarJmp | BTFarRet,

            BTAny = std::underlying_type<BranchType>::type(-1)
        };

        bool Disassemble(ZyanU64 va, const void *buffer, ZyanUSize length, ZydisDisassembledInstruction *instruction)
        {
            return ZYAN_SUCCESS(ZydisDisassembleIntel(ZYDIS_MACHINE_MODE_LEGACY_32, va, buffer, length, instruction));
        };
        bool DisassembleFrom(ZydisDisassembledInstruction *Instruction);

        bool GetDestAddress(ZydisDisassembledInstruction &instruction, ZyanU64 addressOld, ZyanU64 *addressNew) const
        {
            return ZYAN_SUCCESS(ZydisCalcAbsoluteAddress(&instruction.info, &instruction.operands[0], addressOld, addressNew));
        }

        bool Is(ZyanU64 VirtualAddress, std::underlying_type<CodeStatus>::type status) const;

        bool NextVAToExplore(ExplorerResult *const result, ResultData* const ResultData);

        void CheckImmediate(ZydisDisassembledInstruction &Instruction, ZyanU64 Immediate);

        void ResetScanOffsets(ZyanU64 Address, bool force = false);

        ZyanU64 _VirtualStart;
        ZyanU64 _VirtualEnd;
        ZyanU64 _IATStart;
        ZyanU64 _IATEnd;
		size_t _CodeLen;
		const uint8_t *_Code;
        std::underlying_type<CodeStatus>::type *_CodeStatus;
		std::deque<ZyanU64> _OpenEntryPoints;
		std::deque<ZyanU64> _EndOfFunctions;
        std::deque<ZyanU64> _AfterUnconditionalJumps;
        std::unordered_set<ZyanU64> _FromImmediate;
        std::unordered_set<ZyanU64> _DelayedCheckForNanomites;
        std::unordered_set<ZyanU64>::iterator _DelayedCheckForNanomitesIterator;

        ZyanU64 ScanOffsetIATCalls;
        ZyanU64 ScanOffsetsIATMovs;
        ZyanU64 ScanOffsetFunctions;
        ZyanU64 ScanOffsetDelayedNanomites;
        ZyanU64 ScanOffsetBruteforcedNanomites;

	public:
		CodeExplorer(const uint8_t *Code, ZyanU64 VirtualStart, ZyanU64 VirtualEnd, ZyanU64 IATStart, ZyanU64 IATEnd);
		~CodeExplorer();

        void MarkAs(ZyanU64 VirtualAddress, size_t len, std::underlying_type<CodeStatus>::type status) const;
        void MarkAs(ZydisDisassembledInstruction &Instruction, std::underlying_type<CodeStatus>::type status) const;
        void MarkAsExplored(ZydisDisassembledInstruction &Instruction) const { MarkAs(Instruction, CodeStatus::STATUS_EXPLORED); }
        void MarkAsStartOfInstruction(ZydisDisassembledInstruction &Instruction) const { MarkAs(Instruction, CodeStatus::STATUS_START_OF_INSTRUCTION); }
        void MarkAsIgnored(ZydisDisassembledInstruction &Instruction) const { MarkAs(Instruction, CodeStatus::STATUS_IGNORED); }
        void MarkAsFilling(ZydisDisassembledInstruction &Instruction) const { MarkAs(Instruction, CodeStatus::STATUS_FILLING); }
        void MarkAsFoundInImmediate(ZydisDisassembledInstruction &Instruction) const { MarkAs(Instruction, CodeStatus::STATUS_FOUND_IN_IMMEDIATE); }
        void MarkAsStartOfFunction(ZydisDisassembledInstruction &Instruction) const { MarkAs(Instruction, CodeStatus::STATUS_START_OF_FUNCTION); }
        void MarkAsReturn(ZydisDisassembledInstruction &Instruction) const { MarkAs(Instruction, CodeStatus::STATUS_IS_RETURN); }

        bool IsExplored(ZyanU64 VirtualAddress) const { return Is(VirtualAddress, CodeStatus::STATUS_EXPLORED); }
        bool IsStartOfInstruction(ZyanU64 VirtualAddress) const { return Is(VirtualAddress, CodeStatus::STATUS_START_OF_INSTRUCTION); }
        bool IsIgnored(ZyanU64 VirtualAddress) const { return Is(VirtualAddress, CodeStatus::STATUS_IGNORED); }
        bool IsFilling(ZyanU64 VirtualAddress) const { return Is(VirtualAddress, CodeStatus::STATUS_FILLING); }
        bool IsFoundInImmediate(ZyanU64 VirtualAddress) const { return Is(VirtualAddress, CodeStatus::STATUS_FOUND_IN_IMMEDIATE); }
        bool IsStartOfFunction(ZyanU64 VirtualAddress) const { return Is(VirtualAddress, CodeStatus::STATUS_START_OF_FUNCTION); }
        bool IsReturn(ZyanU64 VirtualAddress) const { return Is(VirtualAddress, CodeStatus::STATUS_IS_RETURN); }

        ZyanU64 NextVA(ZydisDisassembledInstruction &Instruction);

		void AddEntryPoint(ZyanU64 VirtualAddress, bool function = false, bool front = false);
        void AddNextAsEntryPoint(ZydisDisassembledInstruction &Instruction, bool front = false);

		ExplorerResult Explore(ResultData *const ResultData);

        bool IsInTextSection(ZyanU64 address) const { return ((_VirtualStart <= address) && (address < _VirtualEnd)); }

        bool IsBranchType(ZydisDisassembledInstruction& instruction, std::underlying_type<BranchType>::type bt) const;

        bool IsRet(ZydisDisassembledInstruction &instruction) const { return IsBranchType(instruction, BTRet); }
        bool IsCall(ZydisDisassembledInstruction &instruction) const { return IsBranchType(instruction, BTCall); }
        bool IsJump(ZydisDisassembledInstruction &instruction) const { return IsBranchType(instruction, BTJmp); }
        bool IsUncondJump(ZydisDisassembledInstruction& instruction) const { return IsBranchType(instruction, BTUncondJmp); }
        bool IsCondJump(ZydisDisassembledInstruction &instruction) const { return !IsUncondJump(instruction); }
        bool IsLoop(ZydisDisassembledInstruction &instruction) const { return IsBranchType(instruction, BTLoop); }
        bool IsInt3(ZydisDisassembledInstruction &instruction) const { return IsBranchType(instruction, BTInt3); }

        bool IsMovMemoryToReg(ZydisDisassembledInstruction &instruction) const
        {
            return (
                    (instruction.info.mnemonic == ZYDIS_MNEMONIC_MOV) && 
                    (instruction.info.operand_count == 2) && 
                    (instruction.operands[0].type == ZYDIS_OPERAND_TYPE_REGISTER) &&
                    (instruction.operands[1].type == ZYDIS_OPERAND_TYPE_MEMORY) &&
                    (instruction.operands[1].mem.disp.has_displacement) &&
                    (instruction.operands[1].mem.base == ZYDIS_REGISTER_NONE)   
                );
        }

        bool IsMemoryAddressFromIAT(ZydisDisassembledInstruction &instruction, ZyanU64 &out_result_address)
        {
            ZyanU64 val = instruction.operands[1].mem.disp.value;

            if ((val < _IATStart) || (val >= _IATEnd))
            {
                return false;
            }

            out_result_address = val;

            return true;
        }

        bool IsUnusual(ZydisDisassembledInstruction &instruction) const;
        bool IsFilling(ZydisDisassembledInstruction &instruction) const;

        bool IsOpType(ZydisDisassembledInstruction &instruction, ZydisOperandType t) const { return (instruction.operands[0].type == t); }
        bool IsOpTypeReg(ZydisDisassembledInstruction &instruction) const { return IsOpType(instruction, ZYDIS_OPERAND_TYPE_REGISTER); }
        bool IsOpTypeMemory(ZydisDisassembledInstruction &instruction) const { return IsOpType(instruction, ZYDIS_OPERAND_TYPE_MEMORY); }

        bool IsNextInstructionInt3(ZydisDisassembledInstruction &Instruction);
        bool IsInt3Slide(ZydisDisassembledInstruction &Instruction);
        bool IsNextInstructionInt3Slide(ZydisDisassembledInstruction &Instruction);
        ZyanU64 NextNonInt3Address(ZydisDisassembledInstruction &Instruction);

        void IgnoreFilling(ZydisDisassembledInstruction &Instruction);
        void IgnoreFillingFromNext(ZydisDisassembledInstruction &Instruction);

        void InvalidateCodeStatus(ZyanU64 VirtualAddress, size_t len);
        void InvalidateCodeStatus(ZydisDisassembledInstruction &Instruction);

        void CheckForInt3SlideAndAddNext(ZydisDisassembledInstruction &Instruction);

        const std::underlying_type<CodeExplorer::CodeStatus>::type* GetCodeStatus();

        double CodeCoverage();
        void DumpCoverageMap();

        bool Verbose = false;
};