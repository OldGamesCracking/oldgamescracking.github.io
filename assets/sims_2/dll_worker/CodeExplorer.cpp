#define ZYDIS_STATIC_BUILD

#include <Windows.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdarg.h>
#include <algorithm>
#include <Zydis.h>
#include "logging.h"
#include "CodeExplorer.h"


CodeExplorer::CodeExplorer(const uint8_t *Code, ZyanU64 VirtualStart, ZyanU64 VirtualEnd, ZyanU64 IATStart, ZyanU64 IATEnd)
{
    _Code = Code;
    _VirtualStart = VirtualStart;
    _VirtualEnd = VirtualEnd;
    _CodeLen = VirtualEnd - VirtualStart;
    _IATStart = IATStart;
    _IATEnd = IATEnd;

    auto codeStatusSize = _CodeLen * sizeof(std::underlying_type<CodeStatus>::type);

    _CodeStatus = (std::underlying_type<CodeStatus>::type*)malloc(codeStatusSize);

    if (_CodeStatus == NULL)
    {
        return;
    }

    memset(_CodeStatus, 0, codeStatusSize);

    _DelayedCheckForNanomitesIterator = _DelayedCheckForNanomites.begin();

    ResetScanOffsets(_VirtualStart, true);
}

CodeExplorer::~CodeExplorer()
{
    if (_CodeStatus == NULL)
    {
        return;
    }

    free(_CodeStatus);
    _CodeStatus = NULL;
}

bool CodeExplorer::DisassembleFrom(ZydisDisassembledInstruction *Instruction)
{
    if (Instruction == nullptr)
    {
        return false;
    }

    auto bufferOffset = Instruction->runtime_address - _VirtualStart;
    auto remaining = _VirtualEnd - Instruction->runtime_address;

    return Disassemble(Instruction->runtime_address, &_Code[bufferOffset], remaining, Instruction);
}

// https://github.com/x64dbg/x64dbg/blob/ef068b4af277b6c12f86ae0f3c05ddb3421a6ff5/src/zydis_wrapper/zydis_wrapper.cpp#L233
bool CodeExplorer::IsBranchType(ZydisDisassembledInstruction &instruction, std::underlying_type<BranchType>::type bt) const
{
    std::underlying_type<BranchType>::type ref = 0;
    const auto &op0 = instruction.operands[0];

    switch (instruction.info.mnemonic)
    {
    case ZYDIS_MNEMONIC_RET:
        ref = (instruction.info.meta.branch_type == ZYDIS_BRANCH_TYPE_FAR) ? BTFarRet : BTRet;
        break;
    case ZYDIS_MNEMONIC_CALL:
        ref = (instruction.info.meta.branch_type == ZYDIS_BRANCH_TYPE_FAR) ? BTFarCall : BTCall;
        break;
    case ZYDIS_MNEMONIC_JMP:
        ref = (instruction.info.meta.branch_type == ZYDIS_BRANCH_TYPE_FAR) ? BTFarJmp : BTUncondJmp;
        break;
    case ZYDIS_MNEMONIC_JB:
    case ZYDIS_MNEMONIC_JBE:
    case ZYDIS_MNEMONIC_JCXZ:
    case ZYDIS_MNEMONIC_JECXZ:
    case ZYDIS_MNEMONIC_JKNZD:
    case ZYDIS_MNEMONIC_JKZD:
    case ZYDIS_MNEMONIC_JL:
    case ZYDIS_MNEMONIC_JLE:
    case ZYDIS_MNEMONIC_JNB:
    case ZYDIS_MNEMONIC_JNBE:
    case ZYDIS_MNEMONIC_JNL:
    case ZYDIS_MNEMONIC_JNLE:
    case ZYDIS_MNEMONIC_JNO:
    case ZYDIS_MNEMONIC_JNP:
    case ZYDIS_MNEMONIC_JNS:
    case ZYDIS_MNEMONIC_JNZ:
    case ZYDIS_MNEMONIC_JO:
    case ZYDIS_MNEMONIC_JP:
    case ZYDIS_MNEMONIC_JRCXZ:
    case ZYDIS_MNEMONIC_JS:
    case ZYDIS_MNEMONIC_JZ:
        ref = BTCondJmp;
        break;
    case ZYDIS_MNEMONIC_SYSCALL:
    case ZYDIS_MNEMONIC_SYSENTER:
        ref = BTSyscall;
        break;
    case ZYDIS_MNEMONIC_SYSRET:
    case ZYDIS_MNEMONIC_SYSEXIT:
        ref = BTSysret;
        break;
    case ZYDIS_MNEMONIC_INT:
        ref = BTInt;
        break;
    case ZYDIS_MNEMONIC_INT3:
        ref = BTInt3;
        break;
    case ZYDIS_MNEMONIC_INT1:
        ref = BTInt1;
        break;
    case ZYDIS_MNEMONIC_IRET:
    case ZYDIS_MNEMONIC_IRETD:
    case ZYDIS_MNEMONIC_IRETQ:
        ref = BTIret;
        break;
    case ZYDIS_MNEMONIC_XBEGIN:
        ref = BTXbegin;
        break;
    case ZYDIS_MNEMONIC_XABORT:
        ref = BTXabort;
        break;
    case ZYDIS_MNEMONIC_RSM:
        ref = BTRsm;
        break;
    case ZYDIS_MNEMONIC_LOOP:
    case ZYDIS_MNEMONIC_LOOPE:
    case ZYDIS_MNEMONIC_LOOPNE:
        ref = BTLoop;
    default:
        ;
    }

    return (bt & ref) != 0;
}

bool CodeExplorer::IsUnusual(ZydisDisassembledInstruction &instruction) const
{
    auto id = instruction.info.mnemonic;
    return instruction.info.attributes & ZYDIS_ATTRIB_IS_PRIVILEGED
        // || instruction.info.meta.category == ZYDIS_CATEGORY_IO
        // || instruction.info.meta.category == ZYDIS_CATEGORY_IOSTRINGOP
        || instruction.info.meta.category == ZYDIS_CATEGORY_RDWRFSGS
        || instruction.info.meta.category == ZYDIS_CATEGORY_SGX
        || instruction.info.meta.category == ZYDIS_CATEGORY_INTERRUPT
        || id == ZYDIS_MNEMONIC_SYSCALL
        || id == ZYDIS_MNEMONIC_SYSENTER
        // || id == ZYDIS_MNEMONIC_CPUID
        // || id == ZYDIS_MNEMONIC_RDTSC
        || id == ZYDIS_MNEMONIC_RDTSCP
        || id == ZYDIS_MNEMONIC_RDRAND
        || id == ZYDIS_MNEMONIC_RDSEED
        || id == ZYDIS_MNEMONIC_RDPID
        || id == ZYDIS_MNEMONIC_RDPKRU
        // || id == ZYDIS_MNEMONIC_RDPRU
        || id == ZYDIS_MNEMONIC_UD1
        || id == ZYDIS_MNEMONIC_UD2
        || id == ZYDIS_MNEMONIC_VMCALL
        || id == ZYDIS_MNEMONIC_VMFUNC
        || id == ZYDIS_MNEMONIC_OUTSB
        || id == ZYDIS_MNEMONIC_OUTSW
        || id == ZYDIS_MNEMONIC_OUTSD
        || id == ZYDIS_MNEMONIC_WRPKRU;
}

bool CodeExplorer::IsFilling(ZydisDisassembledInstruction &instruction) const
{
    switch (instruction.info.mnemonic)
    {
        case ZYDIS_MNEMONIC_NOP:
        case ZYDIS_MNEMONIC_INT3:
            return true;
        default:
            return false;
    }
}

void CodeExplorer::MarkAs(ZyanU64 VirtualAddress, size_t len, std::underlying_type<CodeStatus>::type status) const
{
    auto bufferOffset = VirtualAddress - _VirtualStart;

    for (size_t i = 0; i < len; i++)
    {
        _CodeStatus[bufferOffset + i] |= status;
    }
}

void CodeExplorer::MarkAs(ZydisDisassembledInstruction &Instruction, std::underlying_type<CodeStatus>::type status) const
{
    MarkAs(Instruction.runtime_address, Instruction.info.length, status);
}

bool CodeExplorer::Is(ZyanU64 VirtualAddress, std::underlying_type<CodeStatus>::type status) const
{
    if (!IsInTextSection(VirtualAddress))
    {
        return false;
    }

    auto bufferOffset = VirtualAddress - _VirtualStart;

    return (_CodeStatus[bufferOffset] & status) != 0;
}

ZyanU64 CodeExplorer::NextVA(ZydisDisassembledInstruction &Instruction)
{
    return Instruction.runtime_address + Instruction.info.length;
}

void CodeExplorer::AddEntryPoint(ZyanU64 VirtualAddress, bool function, bool front)
{
    if (!IsInTextSection(VirtualAddress))
    {
        return;
    }

    if (function)
    {
        ZydisDisassembledInstruction instruction;
        instruction.runtime_address = VirtualAddress;
        instruction.info.length = 1;

        MarkAsStartOfFunction(instruction);
    }

    if (IsExplored(VirtualAddress))
    {
        /* We have been here before */

        return;
    }

    if (front)
    {
        _OpenEntryPoints.push_front(VirtualAddress);
    }
    else
    {
        _OpenEntryPoints.push_back(VirtualAddress);
    }
}

void CodeExplorer::AddNextAsEntryPoint(ZydisDisassembledInstruction &Instruction, bool front)
{
    AddEntryPoint(NextVA(Instruction), false, front);
}

bool CodeExplorer::NextVAToExplore(CodeExplorer::ExplorerResult *const result, ResultData *const ResultData)
{
    while (true)
    {
        /*
            Method 1: Known entry points
        */
        if (!_OpenEntryPoints.empty())
        {
            ZyanU64 va_test = *_OpenEntryPoints.begin();
            _OpenEntryPoints.erase(_OpenEntryPoints.begin());

            if (IsExplored(va_test))
            {
                /* We have been here before */

                continue;
            }

            ResultData->ResultAddress = va_test;

            Log.Debug("VA from OpenEntryPoints: %08X", (uint32_t)ResultData->ResultAddress);

            return true;
        }
     
        /*
            Method 2: Try to find new function by 'sliding down' (skipping filling code) after the end of a function
        */
        if (!_EndOfFunctions.empty())
        {
            while (!_EndOfFunctions.empty())
            {
                ZyanU64 va_test = _EndOfFunctions.front();
                _EndOfFunctions.pop_front();

                if (IsExplored(va_test))
                {
                    /* We have been here before */

                    continue;
                }

                Log.Debug("Sliding down @ %08X", (uint32_t)va_test);

                while (va_test < _VirtualEnd)
                {
                    auto bufferOffset = va_test - _VirtualStart;
                    auto remaining = _VirtualEnd - va_test;

                    if (IsExplored(va_test))
                    {
                        break;
                    }

                    if (!Disassemble(va_test, &_Code[bufferOffset], remaining, &ResultData->Instruction))
                    {
                        Log.Line("Error: Unable to disassemble @ %08X", (uint32_t)va_test);

                        ResultData->ResultAddress = va_test;

                        *result = CodeExplorer::ExplorerResult::InvalidCodeInSlideDown;

                        return false;
                    }

                    // Note: Both, IsFilling and IsUnusual check for interrupts, so use them in this order
                    if (IsFilling(ResultData->Instruction))
                    {
                        /* Mark as explored and skip */
                        MarkAsExplored(ResultData->Instruction);
                        MarkAsFilling(ResultData->Instruction);

                        va_test = NextVA(ResultData->Instruction);

                        continue;
                    }

                    if (IsUnusual(ResultData->Instruction))
                    {
                        ResultData->ResultAddress = va_test;

                        *result = CodeExplorer::ExplorerResult::UnusualCodeInSlideDown;

                        return false;
                    }

                    /* Not a filling and we have not been here before -> new code */
                    Log.Debug("Found new code @ %08X", (uint32_t)va_test);

                    AddEntryPoint(va_test);

                    break;
                }

                break;
            }

            continue;
        }
        
        /*
            Method 3: Check addresses that have been found as immediate values of instructions
        */
        if (!_FromImmediate.empty())
        {
            while (!_FromImmediate.empty())
            {
                ZyanU64 va_test = *_FromImmediate.begin();
                _FromImmediate.erase(_FromImmediate.begin());

                if (IsExplored(va_test))
                {
                    /* We have been here before */

                    continue;
                }

                auto bufferOffset = va_test - _VirtualStart;
                auto remaining = _VirtualEnd - va_test;

                if (!Disassemble(va_test, &_Code[bufferOffset], remaining, &ResultData->Instruction))
                {
                    /* Was probably not a code-offset */

                    continue;
                }

                Log.Debug("Testing address from immediate @ %08X", (uint32_t)va_test);

                AddEntryPoint(va_test);

                break;
            }

            continue;
        }
        
        /*
            Method 4: Check if there is filling code after an unconditional Jump -> Jump was probably used as weird return method
        */
        if (!_AfterUnconditionalJumps.empty())
        {
            while (!_AfterUnconditionalJumps.empty())
            {
                ZyanU64 va_test = _AfterUnconditionalJumps.front();
                _AfterUnconditionalJumps.pop_front();

                if (IsExplored(va_test))
                {
                    /* We have been here before */

                    continue;
                }

                auto bufferOffset = va_test - _VirtualStart;
                auto remaining = _VirtualEnd - va_test;

                if (!Disassemble(va_test, &_Code[bufferOffset], remaining, &ResultData->Instruction))
                {
                    continue;
                }

                if (!IsFilling(ResultData->Instruction))
                {
                    continue;
                }

                Log.Debug("Found end of function with JMP @ %08X", (uint32_t)va_test);

                _EndOfFunctions.push_back(va_test);

                break;
            }

            continue;
        }

        /*
            Method 5: Linearely go through the code and see if previously unknown CALLS / Jumps to the IAT can be found 
        */
        bool entryPointFound = false;

        while (ScanOffsetIATCalls < (_VirtualEnd - 6))
        {
            auto bufferOffset = ScanOffsetIATCalls - _VirtualStart;
            
            if (_Code[bufferOffset] == 0xff && ((_Code[bufferOffset + 1] == 0x15) || (_Code[bufferOffset + 1] == 0x25)))
            {
                DWORD thunk = *(DWORD*)&_Code[bufferOffset + 2];

                if ((thunk < _IATStart) || (thunk >= _IATEnd))
                {
                    ScanOffsetIATCalls++;

                    continue;
                }

                if (IsExplored(ScanOffsetIATCalls))
                {
                    ScanOffsetIATCalls++;

                    continue;
                }

                bool isCall = _Code[bufferOffset + 1] == 0x15;

                Log.Debug("Found %s to IAT @ %08X", (isCall ? "CALL" : "JMP"), ScanOffsetIATCalls);
                
                AddEntryPoint(ScanOffsetIATCalls);
                entryPointFound = true;

                break;
            }

            ScanOffsetIATCalls++;
        }

        if (entryPointFound)
        {
            continue;
        }

        /*
            Method 6: Linearely go through the code and search for 'MOV <reg>, dword:[<address_in_iat>]'
        */
        bool movFound = false;

        while (ScanOffsetsIATMovs < (_VirtualEnd - 6))
        {
            if (IsExplored(ScanOffsetsIATMovs))
            {
                ScanOffsetsIATMovs++;

                continue;
            }

            auto bufferOffset = ScanOffsetsIATMovs - _VirtualStart;
            auto remaining = _VirtualEnd - ScanOffsetsIATMovs;

            if (!Disassemble(ScanOffsetsIATMovs, &_Code[bufferOffset], remaining, &ResultData->Instruction))
            {
                ScanOffsetsIATMovs++;

                continue;
            }

            if (!IsMovMemoryToReg(ResultData->Instruction))
            {
                ScanOffsetsIATMovs = NextVA(ResultData->Instruction);

                continue;
            }

            ZyanU64 result_address;

            if (!IsMemoryAddressFromIAT(ResultData->Instruction, result_address))
            {
                ScanOffsetsIATMovs = NextVA(ResultData->Instruction);

                continue;
            }

            Log.Debug("Found new instruction at %08X that points to %08X", (DWORD)ScanOffsetsIATMovs, (DWORD)result_address);

            AddEntryPoint(ScanOffsetsIATMovs);
            movFound = true;

            break;
        }

        if (movFound)
        {
            continue;
        }

        /*
            Method 7: Stupidly go through code and search for CALLs that lead to known functions
        */
        bool functionCallFound = false;

        while (ScanOffsetFunctions < _VirtualEnd)
        {
            auto bufferOffset = ScanOffsetFunctions - _VirtualStart;
            auto remaining = _VirtualEnd - ScanOffsetFunctions;

            if (IsExplored(ScanOffsetFunctions))
            {
                ScanOffsetFunctions++;

                continue;
            }

            if (!Disassemble(ScanOffsetFunctions, &_Code[bufferOffset], remaining, &ResultData->Instruction))
            {
                ScanOffsetFunctions++;

                continue;
            }

            if (IsCall(ResultData->Instruction))
            {
                if (!IsOpTypeReg(ResultData->Instruction))
                {
                    ZyanU64 addressNew;

                    if (GetDestAddress(ResultData->Instruction, ScanOffsetFunctions, &addressNew))
                    {
                        if (!IsOpTypeMemory(ResultData->Instruction))
                        {
                            if (IsStartOfFunction(addressNew))
                            {
                                /* We have found a call to a known function in an unknown part of the code */
                                Log.Debug("Found Call to known function @ %08X", (uint32_t)ScanOffsetFunctions);

                                AddEntryPoint(ScanOffsetFunctions);

                                functionCallFound = true;

                                break;
                            }
                        }
                    }
                }
            }

            ScanOffsetFunctions = NextVA(ResultData->Instruction);
        }

        if (functionCallFound)
        {
            continue;
        }

        /*
            Method 8:   More stupidly try to find new functions by 'sliding down' (skipping filling code) after an intermodular CALL with succeeding filling code
                        that could not yet be interpreted as filling code between compilation units.
                        If the next non-INT3 instruction is found on an un-aligned address, this is seen as indication that the INT3 is indeed a Nanomite
        */
        ZyanU64 alignmentMask = 1;
        bool nanomiteFound = false;

        while (alignmentMask <= 0xff)
        {
            while (_DelayedCheckForNanomitesIterator != _DelayedCheckForNanomites.end())
            {
                ZyanU64 va_test = *_DelayedCheckForNanomitesIterator;

                if (IsExplored(va_test))
                {
                    _DelayedCheckForNanomitesIterator = _DelayedCheckForNanomites.erase(_DelayedCheckForNanomitesIterator);

                    continue;
                }

                ZydisDisassembledInstruction inst;
                inst.runtime_address = va_test;

                if (IsInt3Slide(inst))
                {
                    IgnoreFilling(inst);

                    _DelayedCheckForNanomitesIterator = _DelayedCheckForNanomites.erase(_DelayedCheckForNanomitesIterator);

                    continue;
                }
                else
                {
                    ZyanU64 nextNonInt3 = NextNonInt3Address(inst);

                    if ((alignmentMask & nextNonInt3) != 0)
                    {
                        /* This is not aligned which is uncommon for the start of a function, could be Nanomite */
                        AddEntryPoint(va_test);
                        _DelayedCheckForNanomites.erase(_DelayedCheckForNanomitesIterator);
                        _DelayedCheckForNanomitesIterator = _DelayedCheckForNanomites.begin();

                        nanomiteFound = true;

                        break;
                    }
                }

                _DelayedCheckForNanomitesIterator++;
            }

            if (nanomiteFound)
            {
                /* A possible nanomite was found */
                break;
            }

            _DelayedCheckForNanomitesIterator = _DelayedCheckForNanomites.begin();
            alignmentMask = (alignmentMask << 1) | 1;
        }

        if (nanomiteFound)
        {
            /* A possible nanomite was found */
            continue;
        }

        /*
            Method 9: Last hope. Find all INT3 (0xCC) and try to interpret them as Nanomites
        */
        nanomiteFound = false;

        while (ScanOffsetBruteforcedNanomites < _VirtualEnd)
        {
            auto bufferOffset = ScanOffsetBruteforcedNanomites - _VirtualStart;
            auto remaining = _VirtualEnd - ScanOffsetBruteforcedNanomites;

            if (IsExplored(ScanOffsetBruteforcedNanomites))
            {
                ScanOffsetBruteforcedNanomites++;

                continue;
            }

            if (!Disassemble(ScanOffsetBruteforcedNanomites, &_Code[bufferOffset], remaining, &ResultData->Instruction))
            {
                ScanOffsetBruteforcedNanomites++;

                continue;
            }

            if (!IsInt3(ResultData->Instruction))
            {
                ScanOffsetBruteforcedNanomites = NextVA(ResultData->Instruction);

                continue;
            }

            AddEntryPoint(ScanOffsetBruteforcedNanomites);

            nanomiteFound = true;

            break;
        }

        if (nanomiteFound)
        {
            continue;
        }

        Log.Line("All code searched");

        *result = CodeExplorer::ExplorerResult::DoneExploring;

        break;
    }

    return false;
}

bool CodeExplorer::IsNextInstructionInt3(ZydisDisassembledInstruction& Instruction)
{
    ZydisDisassembledInstruction inst;
    memcpy(&inst, std::addressof(Instruction), sizeof(ZydisDisassembledInstruction));

    inst.runtime_address = NextVA(inst);

    if (!DisassembleFrom(&inst))
    {
        return false;
    }

    return IsInt3(inst);
}

bool CodeExplorer::IsInt3Slide(ZydisDisassembledInstruction &Instruction)
{
    ZydisDisassembledInstruction inst;
    memcpy(&inst, std::addressof(Instruction), sizeof(ZydisDisassembledInstruction));

    while (true)
    {
        if (!DisassembleFrom(&inst))
        {
            return false;
        }

        if (!IsInt3(inst))
        {
            if (inst.runtime_address == Instruction.runtime_address)
            {
                /** There never was an INT3 */
                return false;
            }

            break;
        }

        inst.runtime_address = NextVA(inst);
    }

    return IsStartOfFunction(inst.runtime_address);
}

bool CodeExplorer::IsNextInstructionInt3Slide(ZydisDisassembledInstruction &Instruction)
{
    ZydisDisassembledInstruction inst;
    memcpy(&inst, std::addressof(Instruction), sizeof(ZydisDisassembledInstruction));

    inst.runtime_address = NextVA(inst);

    return IsInt3Slide(inst);
}

ZyanU64 CodeExplorer::NextNonInt3Address(ZydisDisassembledInstruction &Instruction)
{
    ZydisDisassembledInstruction inst;
    memcpy(&inst, std::addressof(Instruction), sizeof(ZydisDisassembledInstruction));

    while (true)
    {
        if (!DisassembleFrom(&inst))
        {
            return inst.runtime_address;
        }

        if (!IsInt3(inst))
        {
            return inst.runtime_address;
        }

        inst.runtime_address = NextVA(inst);
    }
}

void CodeExplorer::IgnoreFilling(ZydisDisassembledInstruction &Instruction)
{
    ZydisDisassembledInstruction inst;
    memcpy(&inst, std::addressof(Instruction), sizeof(ZydisDisassembledInstruction));

    while (true)
    {
        if (!DisassembleFrom(&inst))
        {
            return;
        }

        if (!IsFilling(inst))
        {
            return;
        }

        MarkAsExplored(inst);
        MarkAsFilling(inst);
        MarkAsIgnored(inst);

        inst.runtime_address = NextVA(inst);
    }
}

void CodeExplorer::IgnoreFillingFromNext(ZydisDisassembledInstruction& Instruction)
{
    ZydisDisassembledInstruction inst;
    memcpy(&inst, std::addressof(Instruction), sizeof(ZydisDisassembledInstruction));

    inst.runtime_address = NextVA(inst);

    return IgnoreFilling(inst);
}

void CodeExplorer::InvalidateCodeStatus(ZyanU64 VirtualAddress, size_t len)
{
    auto bufferOffset = VirtualAddress - _VirtualStart;

    for (size_t i = 0; i < len; i++)
    {
        _CodeStatus[bufferOffset + i] = 0;
    }

    ResetScanOffsets(VirtualAddress);
}

void CodeExplorer::InvalidateCodeStatus(ZydisDisassembledInstruction &Instruction)
{
    InvalidateCodeStatus(Instruction.runtime_address, Instruction.info.length);
}

void CodeExplorer::CheckImmediate(ZydisDisassembledInstruction &Instruction, ZyanU64 Immediate)
{
    if (IsInTextSection(Immediate) && !IsExplored(Immediate) && !IsFoundInImmediate(Immediate))
    {
        Log.Debug("\t-> Instruction with immediate operand that is address in text section");

        if (IsUncondJump(Instruction))
        {
            Log.Debug("\t-> Probably a Jump-Table");

            auto bufferOffset = Immediate - _VirtualStart;

            uint32_t *table = (uint32_t *)&_Code[bufferOffset];

            Log.Debug("\t-> Table @ %08X", Immediate);

            auto index = 0;

            while (true)
            {
                uint32_t *entryAddress = &((uint32_t *)Immediate)[index];
                uint32_t entry = table[index];

                Log.Debug("\t-> Entry #%d @ %08X", index, entryAddress);
                Log.Debug("\t-> Entry points to %08X", entry);

                if (!IsInTextSection(entry))
                {
                    break;
                }

                if (!IsExplored(entry))
                {
                    Log.Debug("\t-> Adding %08X from table", entry);

                    _FromImmediate.insert(entry);
                }

                MarkAs((ZyanU64)entryAddress, sizeof(uint32_t), CodeStatus::STATUS_EXPLORED);

                index++;
            }
        }
        else
        {
            MarkAsFoundInImmediate(Instruction);
            _FromImmediate.insert(Immediate);
        }
    }
}

void CodeExplorer::ResetScanOffsets(ZyanU64 Address, bool force)
{
    if (force)
    {
        ScanOffsetIATCalls = Address;
        ScanOffsetsIATMovs = Address;
        ScanOffsetFunctions = Address;
        ScanOffsetDelayedNanomites = Address;
        ScanOffsetBruteforcedNanomites = Address;
    }
    else
    {
        ScanOffsetIATCalls = std::min<ZyanU64>(Address, ScanOffsetIATCalls);
        ScanOffsetsIATMovs = std::min<ZyanU64>(Address, ScanOffsetsIATMovs);
        ScanOffsetFunctions = std::min<ZyanU64>(Address, ScanOffsetFunctions);
        ScanOffsetDelayedNanomites = std::min<ZyanU64>(Address, ScanOffsetDelayedNanomites);
        ScanOffsetBruteforcedNanomites = std::min<ZyanU64>(Address, ScanOffsetBruteforcedNanomites);
    }  
}

CodeExplorer::ExplorerResult CodeExplorer::Explore(ResultData *const ResultData)
{
    if (_CodeStatus == NULL || ResultData == NULL)
    {
        return CodeExplorer::ExplorerResult::DoneExploring;
    }

    ZyanU64 va;
    size_t bufferOffset;
    size_t remaining;

    while (true)
    {
        ExplorerResult result;

        if (!NextVAToExplore(&result, ResultData))
        {
            return result;
        }

        Log.Debug("Starting @ %08X", (uint32_t)ResultData->ResultAddress);

        va = ResultData->ResultAddress;

        bool endOfPathReached = false;

        while (!endOfPathReached)
        {
            if (IsExplored(va))
            {
                break;
            }
            
            bufferOffset = va - _VirtualStart;
            remaining = _VirtualEnd - va;

            if (!Disassemble(va, &_Code[bufferOffset], remaining, &ResultData->Instruction))
            {
                Log.Line("Error: Unable to disassemble @ %08X", (uint32_t)va);

                ResultData->ResultAddress = va;

                return CodeExplorer::ExplorerResult::InvalidCode;
            }

            ZydisDisassembledInstruction &inst = ResultData->Instruction;

            Log.Debug("%08" PRIX64 "  %s", va, inst.text);

            if (IsUnusual(inst))
            {
                ResultData->ResultAddress = va;

                return CodeExplorer::ExplorerResult::UnusualCode;
            }
            
            if (IsRet(inst))
            {
                Log.Debug("\t-> RET @ %08X", (uint32_t)va);

                MarkAsExplored(inst);
                MarkAsReturn(inst);

                /* (Probably) reached the end of a function */
                _EndOfFunctions.push_back(NextVA(inst));

                break;
            }

            if (IsMovMemoryToReg(inst))
            {
                /* Check if in IAT */
                ZyanU64 target;

                if (IsMemoryAddressFromIAT(inst, target))
                {
                    Log.Debug("Found instruction at %08X that points to %08X", (DWORD)va, (DWORD)target);

                    ResultData->ResultAddress = va;
                    ResultData->TargetAddress = target;

                    return CodeExplorer::ExplorerResult::IATCallByRegister;
                }   
            }

            /* Is branch ? */
            if (IsCall(inst) || IsJump(inst) || IsLoop(inst))
            {
                Log.Debug("\t-> branch @ %08X", (uint32_t)va);

                if (!IsOpTypeReg(inst))
                {
                    ZyanU64 addressNew;

                    if (GetDestAddress(inst, va, &addressNew))
                    {
                        if (!IsOpTypeMemory(inst))
                        {
                            if (IsInTextSection(addressNew))
                            {
                                if (IsCall(inst))
                                {
                                    ResultData->ResultAddress = va;
                                    ResultData->TargetAddress = addressNew;

                                    return CodeExplorer::ExplorerResult::CallInterSection;
                                }
                                else
                                {
                                    Log.Debug("\t-> New EP @ %08X", (uint32_t)addressNew);

                                    AddEntryPoint(addressNew, false, true);
                                }
                            }
                            else
                            {
                                ResultData->ResultAddress = va;
                                ResultData->TargetAddress = addressNew;

                                return CodeExplorer::ExplorerResult::JumpOutOfTextSection;
                            }
                        }
                        else
                        {
                            ResultData->ResultAddress = va;
                            ResultData->TargetAddress = addressNew;

                            return CodeExplorer::ExplorerResult::IndirectBranchFromMemory;
                        }
                    }
                }

                if (IsUncondJump(inst))
                {
                    /* Normal execution path ends here */
                    Log.Debug("Unkonditional jump, execution ends here");

                    _AfterUnconditionalJumps.push_back(NextVA(inst));

                    endOfPathReached = true;
                }
            }

            /* Is an address in one of the operands? */
            for (auto i = 0; i < inst.info.operand_count_visible; i++)
            {
                if (inst.operands[i].type == ZYDIS_OPERAND_TYPE_IMMEDIATE)
                {
                    const ZyanU64 val = inst.operands[i].imm.value.u;

                    CheckImmediate(inst, val);
                }
                else if (inst.operands[i].type == ZYDIS_OPERAND_TYPE_MEMORY)
                {
                    ZyanU64 dest = inst.operands[i].mem.disp.value;

                    if (inst.operands[i].mem.base == ZYDIS_REGISTER_RIP)
                    {
                        dest = NextVA(inst);
                    }

                    CheckImmediate(inst, dest);
                }
            }
            
            MarkAsExplored(inst);

            va = NextVA(inst);
        }
    }

    return CodeExplorer::ExplorerResult::DoneExploring;
}

void CodeExplorer::CheckForInt3SlideAndAddNext(ZydisDisassembledInstruction &Instruction)
{
    if (IsNextInstructionInt3(Instruction))
    {
        if (IsNextInstructionInt3Slide(Instruction))
        {
            IgnoreFillingFromNext(Instruction);
        }
        else
        {
            /* Remember this for later in case the function was just not found yet */
            _DelayedCheckForNanomites.insert(NextVA(Instruction));
            _DelayedCheckForNanomitesIterator = _DelayedCheckForNanomites.begin();
        }
    }
    else
    {
        /* Probably normal call */
        AddNextAsEntryPoint(Instruction);
    }
}

const std::underlying_type<CodeExplorer::CodeStatus>::type* CodeExplorer::GetCodeStatus()
{
    return _CodeStatus;
}

double CodeExplorer::CodeCoverage()
{
    if ((_CodeStatus == nullptr) || (_CodeLen == 0))
    {
        return 0.0f;
    }

    size_t explored = 0;

    for (size_t i = 0; i < _CodeLen; i++)
    {
        if ((_CodeStatus[i] & STATUS_EXPLORED) != 0)
        {
            explored++;
        }
    }

    return ((double)explored / (double)_CodeLen) * 100.0f;
}

void CodeExplorer::DumpCoverageMap()
{
    if ((_CodeStatus == nullptr) || (_CodeLen == 0))
    {
        return;
    }

    FILE *f;

    if (fopen_s(&f, "exploration.bin", "a") != NULL)
    {
        return;
    }

    fwrite(_CodeStatus, sizeof(uint8_t), _CodeLen, f);

    fclose(f);
}