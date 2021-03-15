#include <cstdint>
#include <vector>
#include <algorithm>
#include <optional>

#include "binaryninjaapi.h"
#include "lowlevelilinstruction.h"

#include "disasm.h"
#include "branches.h"
#include "il.h"

using namespace BinaryNinja;


class LinuxSHPlatform : public Platform {
  public:
	LinuxSHPlatform(Architecture* arch): Platform(arch, "linux-superh") {
		Ref<CallingConvention> cc;
        cc = arch->GetCallingConventionByName("default");
		if (cc)
		{
			RegisterDefaultCallingConvention(cc);
			RegisterCdeclCallingConvention(cc);
			RegisterFastcallCallingConvention(cc);
			RegisterStdcallCallingConvention(cc);
		}

		cc = arch->GetCallingConventionByName("linux-syscall");
		if (cc) {
			SetSystemCallConvention(cc);
        }
	}
};

class SuperHCallingConv : public CallingConvention {
  public:
    SuperHCallingConv(Architecture *arch) : CallingConvention(arch, "default") {};

    std::vector<uint32_t> GetIntegerArgumentRegisters() override {
        return {
            SHReg::R4,
            SHReg::R5,
            SHReg::R6,
            SHReg::R7,
        };
    }

    std::vector<uint32_t> GetCallerSavedRegisters() override {
        return {};
    }

    std::vector<uint32_t> GetCalleeSavedRegisters() override {
        return {
            SHReg::R8,
            SHReg::R9,
            SHReg::R10,
            SHReg::R11,
            SHReg::R12,
            SHReg::R13,
            SHReg::R14,
            SHReg::R15
        };
    }

    // uint32_t GetGlobalPointerRegister() override {
    //     return SHReg::GBR;
    // }

    uint32_t GetIntegerReturnValueRegister() override {
        return SHReg::R0;
    }

    bool IsStackAdjustedOnReturn() override {
        return true;
    }
};

enum ElfSHType : uint32_t {
    R_SH_DIR32 = 1,
    R_SH_COPY = 162,
    R_SH_GLOB_DAT = 163,
    R_SH_JMP_SLOT = 164,
    R_SH_RELATIVE = 165,
};

class SuperHRelocationHandler : public RelocationHandler {
  public:
    bool GetRelocationInfo(Ref<BinaryView> view, Ref<Architecture> arch, std::vector<BNRelocationInfo>& result) override {
        for (size_t i = 0; i < result.size(); i++) {
            result[i].type = BNRelocationType::StandardRelocationType;
            switch (result[i].nativeType) {
            case ElfSHType::R_SH_COPY:
                result[i].type = BNRelocationType::ELFCopyRelocationType;
                break;
            case ElfSHType::R_SH_GLOB_DAT:
                result[i].type = BNRelocationType::ELFGlobalRelocationType;
                break;
            case ElfSHType::R_SH_JMP_SLOT:
                result[i].type = BNRelocationType::ELFJumpSlotRelocationType;
                break;
            case ElfSHType::R_SH_DIR32:
                result[i].pcRelative = false;
                result[i].baseRelative = false;
                result[i].hasSign = false;
                result[i].size = 4;
                result[i].truncateSize = 4;
                break;
            default:
                break;
            }
        }
        return true;
    }
};

class ShImportedFunctionRecognizer: public FunctionRecognizer {
	private:
	bool RecognizeELFPLTEntries(BinaryView* data, Function* func, LowLevelILFunction* il) {
        // 0   R0 = [(4 << 2) + (0x400f50 & 0xfffffffc) + 4 ].d
        // 1   R0 = [R0 {strrchr@GOT}].d
        // 2   R1 = [(2 << 2) + (0x400f54 & 0xfffffffc) + 4].d
        // 3   temp1.d = R0
        // 4   R0 = R1
        // 5   <return> tailcall(temp1.d)

        if (il->GetInstructionCount() != 6) {
            return false;
        }

        auto tmp_insn = il->GetInstruction(0);
        if (tmp_insn.operation != LLIL_SET_REG) {
            return false;
        }

        auto tmp_op = tmp_insn.GetSourceExpr<LLIL_SET_REG>();
        if (tmp_op.operation != LLIL_SX) {
            return false;
        }
        auto inner_op = tmp_op.GetSourceExpr<LLIL_SX>();
        if (inner_op.operation != LLIL_LOAD) {
            return false;
        }

        tmp_insn = il->GetInstruction(1);
        if (tmp_insn.operation != LLIL_SET_REG) {
            return false;
        }
        tmp_op = tmp_insn.GetSourceExpr<LLIL_SET_REG>();
        if (tmp_op.operation != LLIL_LOAD) {
            return false;
        }

        auto got_const_val = tmp_op.GetValue();

        if (got_const_val.state != BNRegisterValueType::ImportedAddressValue) {
            return false;
        }
        auto got_const = got_const_val.value;

        tmp_insn = il->GetInstruction(2);
        if (tmp_insn.operation != LLIL_SET_REG) {
            return false;
        }
        tmp_insn = il->GetInstruction(5);
		if((tmp_insn.operation != LLIL_JUMP) && (tmp_insn.operation != LLIL_TAILCALL)) {
			return false;
        }

		Ref<Symbol> sym = data->GetSymbolByAddress(got_const);
		if (!sym) {
			return false;
		}
		if (sym->GetType() != ImportAddressSymbol) {
			return false;
		}

        // Populate the type info from the extern/got entry to the created PLT stub function
        Confidence<Ref<Type>> type = nullptr;
        DataVariable var;
        if (data->GetDataVariableAtAddress(sym->GetAddress(), var) &&
            var.type->GetClass() == PointerTypeClass) {

            auto childType = var.type->GetChildType();
            if (childType && childType->GetClass() == FunctionTypeClass &&
                childType.GetConfidence() >= BN_MINIMUM_CONFIDENCE) {

			    type = var.type->GetChildType();
            }

        }

        auto func_sym = Symbol::ImportedFunctionFromImportAddressSymbol(sym, func->GetStart());
		data->DefineAutoSymbol(func_sym);
		func->ApplyImportedTypes(func_sym, type);
        return true;
    }

  public:
    virtual bool RecognizeLowLevelIL(BinaryView* data, Function* func, LowLevelILFunction* il) override {
		if (RecognizeELFPLTEntries(data, func, il))
			return true;
		return false;
	}

};

class SuperHArchitecture : public Architecture {
  public:
    static const uint32_t EM_SH = 42;

    SuperHArchitecture(const std::string &name) : Architecture(name) {};

    size_t GetAddressSize() const override {
        return 4;
    }
    BNEndianness GetEndianness() const override {
        return LittleEndian;
    }
    size_t GetDefaultIntegerSize() const override {
        return 4;
    }
    size_t GetInstructionAlignment() const override {
        return 2;
    }
    size_t GetMaxInstructionLength() const override {
        return 4;
    }
    uint32_t GetStackPointerRegister() override {
        return SHReg::R15;
    }
    uint32_t GetLinkRegister() override {
        return SHReg::PR;
    }
    std::vector<uint32_t> GetGlobalRegisters() override {
        return {
            SHReg::GBR
        };
    }
    std::vector<uint32_t> GetSystemRegisters() override {
        return {
            SHReg::MACH,
            SHReg::MACL,
            SHReg::PR,
            SHReg::PC,
            SHReg::FPSCR,
            SHReg::FPUL
        };
    }
    std::vector<uint32_t> GetAllRegisters() override {
        return {
            SHReg::R0,
            SHReg::R1,
            SHReg::R2,
            SHReg::R3,
            SHReg::R4,
            SHReg::R5,
            SHReg::R6,
            SHReg::R7,
            SHReg::R8,
            SHReg::R9,
            SHReg::R10,
            SHReg::R11,
            SHReg::R12,
            SHReg::R13,
            SHReg::R14,
            SHReg::R15,
            SHReg::R0_BANK,
            SHReg::R1_BANK,
            SHReg::R2_BANK,
            SHReg::R3_BANK,
            SHReg::R4_BANK,
            SHReg::R5_BANK,
            SHReg::R6_BANK,
            SHReg::R7_BANK,
            SHReg::R8_BANK,
            SHReg::R9_BANK,
            SHReg::R10_BANK,
            SHReg::R11_BANK,
            SHReg::R12_BANK,
            SHReg::R13_BANK,
            SHReg::R14_BANK,
            SHReg::R15_BANK,
            SHReg::FR0,
            SHReg::FR1,
            SHReg::FR2,
            SHReg::FR3,
            SHReg::FR4,
            SHReg::FR5,
            SHReg::FR6,
            SHReg::FR7,
            SHReg::FR8,
            SHReg::FR9,
            SHReg::FR10,
            SHReg::FR11,
            SHReg::FR12,
            SHReg::FR13,
            SHReg::FR14,
            SHReg::FR15,
            SHReg::FV0,
            SHReg::FV4,
            SHReg::FV8,
            SHReg::FV12,
            SHReg::DR0,
            SHReg::DR2,
            SHReg::DR4,
            SHReg::DR6,
            SHReg::DR8,
            SHReg::DR10,
            SHReg::DR12,
            SHReg::DR14,
            SHReg::XF0,
            SHReg::XF1,
            SHReg::XF2,
            SHReg::XF3,
            SHReg::XF4,
            SHReg::XF5,
            SHReg::XF6,
            SHReg::XF7,
            SHReg::XF8,
            SHReg::XF9,
            SHReg::XF10,
            SHReg::XF11,
            SHReg::XF12,
            SHReg::XF13,
            SHReg::XF14,
            SHReg::XF15,
            SHReg::XMTRX,
            SHReg::XD0,
            SHReg::XD2,
            SHReg::XD4,
            SHReg::XD6,
            SHReg::XD8,
            SHReg::XD10,
            SHReg::XD12,
            SHReg::XD14,
            SHReg::FPUL,
            SHReg::A0,
            SHReg::A1,
            SHReg::M0,
            SHReg::M1,
            SHReg::SR,
            SHReg::SSR,
            SHReg::SPC,
            SHReg::GBR,
            SHReg::VBR,
            SHReg::SGR,
            SHReg::DBR,
            SHReg::RE,
            SHReg::RS,
            SHReg::MOD,
            SHReg::TBR,
            SHReg::MACH,
            SHReg::MACL,
            SHReg::PR,
            SHReg::DSR,
            SHReg::X0,
            SHReg::X1,
            SHReg::Y0,
            SHReg::Y1,
            SHReg::PC,
            SHReg::FPSCR,
            SHReg::FPUL
        };
    }
    std::vector<uint32_t> GetFullWidthRegisters() override {
        return {
            SHReg::R0,
            SHReg::R1,
            SHReg::R2,
            SHReg::R3,
            SHReg::R4,
            SHReg::R5,
            SHReg::R6,
            SHReg::R7,
            SHReg::R8,
            SHReg::R9,
            SHReg::R10,
            SHReg::R11,
            SHReg::R12,
            SHReg::R13,
            SHReg::R14,
            SHReg::R15
        };
    }
    std::string GetRegisterName(uint32_t reg) override {
        return get_reg_name(reg);
    }
    BNRegisterInfo GetRegisterInfo(uint32_t reg) override {
        return BNRegisterInfo {reg, 0, 4};
    };

    std::vector<uint32_t> GetAllFlags() override {
        return {
            SHFlags::NONE,
            SHFlags::T_FLAG,
            SHFlags::LDST,
        };
    }

    std::string GetFlagName(uint32_t flag) override {
        switch (flag) {
        case SHFlags::NONE:
            return "";
        case SHFlags::T_FLAG:
            return "T";
        case SHFlags::LDST:
            return "LDST";
        default:
            return "UNKNOWN";
        }
    }

	BNFlagRole GetFlagRole(uint32_t flag, uint32_t) override {
		switch (flag) {
		case SHFlags::T_FLAG:
			return ZeroFlagRole;
		default:
			return SpecialFlagRole;
		}
	}

	std::vector<uint32_t> GetAllFlagWriteTypes() override {
		return {
			SHFlagGroups::IL_FLAGWRITE_ALL
		};
	}

	std::string GetFlagWriteTypeName(uint32_t flags) override {
		switch (flags) {
		case SHFlagGroups::IL_FLAGWRITE_ALL:
			return "*";
		default:
			return "";
		}
	}
	std::vector<uint32_t> GetFlagsWrittenByFlagWriteType(uint32_t flags) override {
		switch (flags) {
		case IL_FLAGWRITE_ALL:
			return { SHFlags::T_FLAG };
		default:
			return {};
		}
	}

	std::vector<uint32_t> GetFlagsRequiredForFlagCondition(BNLowLevelILFlagCondition cond, uint32_t) override {
		switch (cond) {
        case LLFC_E:
        case LLFC_NE:
            return { SHFlags::T_FLAG };
        default:
            return {};
        }
    }

    bool GetInstructionText(const uint8_t* data, uint64_t addr, size_t& len, std::vector<InstructionTextToken> &result) override {
        auto insn_res = disassemble(data, addr, len);
        if (!insn_res) {
            len = 2;
            result.emplace_back(BNInstructionTextTokenType::TextToken, "<unknown>");
            return false;
        }
        auto insn = *insn_res;
        len = 2;

        for (const auto &token : insn.tokens) {
            result.emplace_back(token.first, token.second);
        }

        return true;
    }

    bool GetInstructionInfo(const uint8_t *data, uint64_t addr, size_t maxLen, InstructionInfo &result) override {
        auto insn_res = disassemble(data, addr, maxLen);
        if (!insn_res) {
            result.length = 2;
            return false;
        }
        auto insn = *insn_res;
        result.length = 2;

        find_branches(insn, result);

        return true;
    }

    bool GetInstructionLowLevelIL(const uint8_t* data, uint64_t addr, size_t& len, LowLevelILFunction& il) override {
        auto insn_res = disassemble(data, addr, len);
        if (!insn_res) {
            len = 2;
            return false;
        }
        auto insn = *insn_res;
        uint8_t total_size = insn.size;
        uint32_t clobbered = BN_INVALID_REGISTER;
        size_t delay_set_flag_idx = 0;
        uint32_t clobbered_flag = SHFlags::NONE;
        ExprId nop_id = 0;

        // lift delay slot first
        if (len > 2 && insn.is_delay) {
            auto delay_insn_res = disassemble(data + insn.size, addr + insn.size, len - insn.size);
            if (!delay_insn_res) {
                il.AddInstruction(il.Unimplemented());
                total_size += 2;
            }
            else {
                // Imperfect solution

                // jmp @r0
                // mov r1, r0
                //   to:
                // r0 -> TMPREG1
                // mov r1 -> ro
                // jmp @TMPREG1

                // cmp/eq 0xff, R0
                // bf/s 0x40109c
                // cmp/eq 0xfd, R0
                //  to:
                // cmp/eq 0xff, R0
                // if (!t)
                //   cmp/eq 0xfd, R0
                //   jump()


                nop_id = il.Nop();
                il.AddInstruction(nop_id);

                auto delay_insn = *delay_insn_res;
                lift(this, delay_insn, il);
                total_size += delay_insn.size;
                auto idx = il.GetInstructionCount() - 1;
                auto last_insn = il.GetInstruction(idx);

                if (last_insn.operation == LLIL_SET_FLAG) {
                    delay_set_flag_idx = last_insn.exprIndex;
                }
            }
        }

        lift(this, insn, il);

        if (insn.is_delay and nop_id != 0) {
            size_t instrIdx = 0;
            if (delay_set_flag_idx == 0) {
                instrIdx = il.GetInstructionCount() - 1;
                if (instrIdx != 0) {
                    auto delayed = il.GetInstruction(instrIdx - 1);
                    // LogInfo("checking insnIdx: %lu at: 0x%x", instrIdx - 1, insn.addr);
                    if (delayed.operation == LLIL_SET_REG) {
                        clobbered = delayed.GetDestRegister<LLIL_SET_REG>();
                    }
                }
            } else {
                instrIdx = il.GetInstructionCount() - 3;
                auto test_insn = il.GetInstruction(instrIdx);
                if (test_insn.operation == LLIL_IF) {
                    nop_id = instrIdx + 1;
                    auto nop_insn = il.GetInstruction(nop_id);
                    if (nop_insn.operation == LLIL_NOP) {
                        clobbered_flag = SHFlags::T_FLAG;
                        nop_id = nop_insn.exprIndex;
                    }
                }
            }

            if (clobbered != BN_INVALID_REGISTER) {
                // LogInfo("Replacing reg: %d at: 0x%x", clobbered, insn.addr);
                il.ReplaceExpr(
                    nop_id,
                    il.SetRegister(
                        4,
                        LLIL_TEMP(1),
                        il.Register(
                            4,
                            clobbered
                        )
                    )
                );

                auto branch = il.GetInstruction(instrIdx);

                if (branch.operation == LLIL_JUMP || branch.operation == LLIL_CALL) {
                    branch.VisitExprs([&](const LowLevelILInstruction& expr) -> bool {
                        if (expr.operation == LLIL_REG && expr.GetSourceRegister<LLIL_REG>() == clobbered)
                        {
                            il.ReplaceExpr(expr.exprIndex, il.Register(expr.size, LLIL_TEMP(1)));
                        }
                        return true;
                    });
                }
            }
            else if (delay_set_flag_idx && clobbered_flag != SHFlags::NONE) {
                il.ReplaceExpr(
                    nop_id,
                    delay_set_flag_idx
                );

                il.ReplaceExpr(
                    delay_set_flag_idx,
                    il.Nop()
                );

            }
        }
        len = total_size;
        return true;
    }

};


extern "C" {

BN_DECLARE_CORE_ABI_VERSION

BINARYNINJAPLUGIN bool CorePluginInit() {
    Architecture *superh = new SuperHArchitecture("superh");
    Architecture::Register(superh);

    // Register calling convention.
    Ref<CallingConvention> conv;
    conv = new SuperHCallingConv(superh);
    superh->RegisterCallingConvention(conv);
    superh->SetDefaultCallingConvention(conv);

    superh->RegisterFunctionRecognizer(new ShImportedFunctionRecognizer());
    superh->SetBinaryViewTypeConstant("ELF", "R_COPY", ElfSHType::R_SH_COPY);
    superh->SetBinaryViewTypeConstant("ELF", "R_GLOBAL_DATA", ElfSHType::R_SH_GLOB_DAT);
    superh->SetBinaryViewTypeConstant("ELF", "R_JUMP_SLOT", ElfSHType::R_SH_JMP_SLOT);
    superh->SetBinaryViewTypeConstant("ELF", "R_SH_RELATIVE", ElfSHType::R_SH_RELATIVE);
    superh->SetBinaryViewTypeConstant("ELF", "R_SH_DIR32", ElfSHType::R_SH_DIR32);

    superh->RegisterRelocationHandler("ELF", new SuperHRelocationHandler());

    // Register binary format parsers.
    BinaryViewType::RegisterArchitecture("ELF", SuperHArchitecture::EM_SH, LittleEndian, superh);


    // Register a linux-superh platform
    Ref<Platform> platform;
    platform = new LinuxSHPlatform(superh);
    Platform::Register("linux", platform);
    BinaryViewType::RegisterPlatform("ELF", 0, superh, platform);
    BinaryViewType::RegisterPlatform("ELF", 3, superh, platform);


    return true;
}

}