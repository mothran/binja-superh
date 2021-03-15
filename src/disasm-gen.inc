#pragma once
#include <vector>
#include <optional>
#include <sstream>
inline std::string int_to_hex(uint32_t value) {
    std::stringstream stream;
    stream << "0x" << std::hex << value;
    return stream.str();
}

inline uint32_t label_disp(uint32_t d, uint32_t addr, uint32_t patt, uint32_t mask) {
   int32_t disp = 0;
   if ((d & patt) == 0)
       disp = mask & d;
   else
       disp = ~mask | d;
   return (disp << 1) + 4 + addr;
}


enum class SHOpCode {
    op_mov,
    op_movi20,
    op_movi20s,
    op_mova,
    op_mov_w,
    op_mov_l,
    op_mov_b,
    op_movu_b,
    op_movu_w,
    op_movco_l,
    op_movli_l,
    op_movua_l,
    op_movml_l,
    op_movmu_l,
    op_movrt,
    op_movt,
    op_nott,
    op_swap_b,
    op_swap_w,
    op_xtrct,
    op_band_b,
    op_bandnot_b,
    op_bclr_b,
    op_bclr,
    op_bld_b,
    op_bld,
    op_bldnot_b,
    op_bor_b,
    op_bornot_b,
    op_bset_b,
    op_bset,
    op_bst_b,
    op_bst,
    op_bxor_b,
    op_add,
    op_addc,
    op_addv,
    op_cmp_eq,
    op_cmp_hs,
    op_cmp_ge,
    op_cmp_hi,
    op_cmp_gt,
    op_cmp_pl,
    op_cmp_pz,
    op_cmp_str,
    op_clips_b,
    op_clips_w,
    op_clipu_b,
    op_clipu_w,
    op_div0s,
    op_div0u,
    op_div1,
    op_divs,
    op_divu,
    op_dmuls_l,
    op_dmulu_l,
    op_dt,
    op_exts_b,
    op_exts_w,
    op_extu_b,
    op_extu_w,
    op_mac_l,
    op_mac_w,
    op_mul_l,
    op_mulr,
    op_muls_w,
    op_mulu_w,
    op_neg,
    op_negc,
    op_sub,
    op_subc,
    op_subv,
    op_and,
    op_and_b,
    op_not,
    op_or,
    op_or_b,
    op_tas_b,
    op_tst,
    op_tst_b,
    op_xor,
    op_xor_b,
    op_rotcl,
    op_rotcr,
    op_rotl,
    op_rotr,
    op_shad,
    op_shal,
    op_shar,
    op_shld,
    op_shll,
    op_shll2,
    op_shll8,
    op_shll16,
    op_shlr,
    op_shlr2,
    op_shlr8,
    op_shlr16,
    op_bf,
    op_bf_s,
    op_bt,
    op_bt_s,
    op_bra,
    op_braf,
    op_bsr,
    op_bsrf,
    op_jmp,
    op_jsr,
    op_jsr_n,
    op_rts,
    op_rts_n,
    op_rtv_n,
    op_clrmac,
    op_clrs,
    op_clrt,
    op_icbi,
    op_ldbank,
    op_ldc,
    op_ldc_l,
    op_ldre,
    op_ldrs,
    op_lds,
    op_lds_l,
    op_ldtlb,
    op_movca_l,
    op_nop,
    op_ocbi,
    op_ocbp,
    op_ocbwb,
    op_pref,
    op_prefi,
    op_resbank,
    op_rte,
    op_setrc,
    op_sets,
    op_sett,
    op_sleep,
    op_stbank,
    op_stc,
    op_stc_l,
    op_sts,
    op_sts_l,
    op_synco,
    op_trapa,
    op_fmov,
    op_fmov_s,
    op_fmov_d,
    op_fldi0,
    op_fldi1,
    op_flds,
    op_fsts,
    op_fabs,
    op_fneg,
    op_fadd,
    op_fsub,
    op_fmul,
    op_fmac,
    op_fdiv,
    op_fsqrt,
    op_fcmp_eq,
    op_fcmp_gt,
    op_float,
    op_ftrc,
    op_fipr,
    op_ftrv,
    op_fsrra,
    op_fsca,
    op_fcnvds,
    op_fcnvsd,
    op_frchg,
    op_fschg,
    op_fpchg,
    op_nopx,
    op_movx_w,
    op_nopy,
    op_movy_w,
    op_movs_w,
    op_movs_l,
    op_pabs,
    op_padd,
    op_dct_padd,
    op_dcf_padd,
    op_paddc,
    op_pclr,
    op_dct_pclr,
    op_dcf_pclr,
    op_pcmp,
    op_pcopy,
    op_dct_pcopy,
    op_dcf_pcopy,
    op_pneg,
    op_dct_pneg,
    op_dcf_pneg,
    op_psub,
    op_dct_psub,
    op_dcf_psub,
    op_psubc,
    op_pdec,
    op_dct_pdec,
    op_dcf_pdec,
    op_pinc,
    op_dct_pinc,
    op_dcf_pinc,
    op_pdmsb,
    op_dct_pdmsb,
    op_dcf_pdmsb,
    op_prnd,
    op_pand,
    op_dct_pand,
    op_dcf_pand,
    op_por,
    op_dct_por,
    op_dcf_por,
    op_pxor,
    op_dct_pxor,
    op_dcf_pxor,
    op_pmuls,
    op_psha,
    op_dct_psha,
    op_dcf_psha,
    op_pshl,
    op_dct_pshl,
    op_dcf_pshl,
    op_plds,
    op_dct_plds,
    op_dcf_plds,
    op_psts,
    op_dct_psts,
    op_dcf_psts,
};

enum SHReg : uint32_t {
    R0 = 0,
    R1 = 1,
    R2 = 2,
    R3 = 3,
    R4 = 4,
    R5 = 5,
    R6 = 6,
    R7 = 7,
    R8 = 8,
    R9 = 9,
    R10 = 10,
    R11 = 11,
    R12 = 12,
    R13 = 13,
    R14 = 14,
    R15 = 15,
    R0_BANK = 16,
    R1_BANK = 17,
    R2_BANK = 18,
    R3_BANK = 19,
    R4_BANK = 20,
    R5_BANK = 21,
    R6_BANK = 22,
    R7_BANK = 23,
    R8_BANK = 24,
    R9_BANK = 25,
    R10_BANK = 26,
    R11_BANK = 27,
    R12_BANK = 28,
    R13_BANK = 29,
    R14_BANK = 30,
    R15_BANK = 31,
    FR0 = 32,
    FR1 = 33,
    FR2 = 34,
    FR3 = 35,
    FR4 = 36,
    FR5 = 37,
    FR6 = 38,
    FR7 = 39,
    FR8 = 40,
    FR9 = 41,
    FR10 = 42,
    FR11 = 43,
    FR12 = 44,
    FR13 = 45,
    FR14 = 46,
    FR15 = 47,
    FV0 = 48,
    FV4 = 49,
    FV8 = 50,
    FV12 = 51,
    DR0 = 52,
    DR2 = 53,
    DR4 = 54,
    DR6 = 55,
    DR8 = 56,
    DR10 = 57,
    DR12 = 58,
    DR14 = 59,
    XF0 = 60,
    XF1 = 61,
    XF2 = 62,
    XF3 = 63,
    XF4 = 64,
    XF5 = 65,
    XF6 = 66,
    XF7 = 67,
    XF8 = 68,
    XF9 = 69,
    XF10 = 70,
    XF11 = 71,
    XF12 = 72,
    XF13 = 73,
    XF14 = 74,
    XF15 = 75,
    XMTRX = 76,
    XD0 = 77,
    XD2 = 78,
    XD4 = 79,
    XD6 = 80,
    XD8 = 81,
    XD10 = 82,
    XD12 = 83,
    XD14 = 84,
    A0 = 85,
    A1 = 86,
    M0 = 87,
    M1 = 88,
    SR = 89,
    SSR = 90,
    SPC = 91,
    GBR = 92,
    VBR = 93,
    SGR = 94,
    DBR = 95,
    RE = 96,
    RS = 97,
    MOD = 98,
    TBR = 99,
    MACH = 100,
    MACL = 101,
    PR = 102,
    DSR = 103,
    X0 = 104,
    X1 = 105,
    Y0 = 106,
    Y1 = 107,
    PC = 108,
    FPSCR = 109,
    FPUL = 110,
    END_REG = 111,
    InvalidReg  = 112
};
static const char *sh_reg_strs[] = {
    "R0",
    "R1",
    "R2",
    "R3",
    "R4",
    "R5",
    "R6",
    "R7",
    "R8",
    "R9",
    "R10",
    "R11",
    "R12",
    "R13",
    "R14",
    "R15",
    "R0_BANK",
    "R1_BANK",
    "R2_BANK",
    "R3_BANK",
    "R4_BANK",
    "R5_BANK",
    "R6_BANK",
    "R7_BANK",
    "R8_BANK",
    "R9_BANK",
    "R10_BANK",
    "R11_BANK",
    "R12_BANK",
    "R13_BANK",
    "R14_BANK",
    "R15_BANK",
    "FR0",
    "FR1",
    "FR2",
    "FR3",
    "FR4",
    "FR5",
    "FR6",
    "FR7",
    "FR8",
    "FR9",
    "FR10",
    "FR11",
    "FR12",
    "FR13",
    "FR14",
    "FR15",
    "FV0",
    "FV4",
    "FV8",
    "FV12",
    "DR0",
    "DR2",
    "DR4",
    "DR6",
    "DR8",
    "DR10",
    "DR12",
    "DR14",
    "XF0",
    "XF1",
    "XF2",
    "XF3",
    "XF4",
    "XF5",
    "XF6",
    "XF7",
    "XF8",
    "XF9",
    "XF10",
    "XF11",
    "XF12",
    "XF13",
    "XF14",
    "XF15",
    "XMTRX",
    "XD0",
    "XD2",
    "XD4",
    "XD6",
    "XD8",
    "XD10",
    "XD12",
    "XD14",
    "A0",
    "A1",
    "M0",
    "M1",
    "SR",
    "SSR",
    "SPC",
    "GBR",
    "VBR",
    "SGR",
    "DBR",
    "RE",
    "RS",
    "MOD",
    "TBR",
    "MACH",
    "MACL",
    "PR",
    "DSR",
    "X0",
    "X1",
    "Y0",
    "Y1",
    "PC",
    "FPSCR",
    "FPUL",
    "END_REG",
    "InvalidReg"
};

inline std::optional<SHInsn> disasm_one(uint16_t insn, uint32_t addr) {
    if ((insn & 0xf00f) == 0x6003) {
        return SHInsn(
            SHOpCode::op_mov,
            {
                {InstructionToken, "mov"},
                {TextToken, " "},
                {RegisterToken, "R" + std::to_string(((insn & 0xf0) >> 0x4)) },
                {OperandSeparatorToken, ", "},
                {RegisterToken, "R" + std::to_string(((insn & 0xf00) >> 0x8)) }
            },
            {
                SHOper(OpType::REG, SHReg(R0 + ((insn & 0xf0) >> 0x4)), 0, false, false, false, 0, 4),
                SHOper(OpType::REG, SHReg(R0 + ((insn & 0xf00) >> 0x8)), 0, false, false, false, 0, 4)
            },
            false,
            2,
            addr
        );
    }

    if ((insn & 0xf000) == 0xe000) {
        return SHInsn(
            SHOpCode::op_mov,
            {
                {InstructionToken, "mov"},
                {TextToken, " "},
                {PossibleAddressToken, int_to_hex((insn & 0xff))},
                {OperandSeparatorToken, ", "},
                {RegisterToken, "R" + std::to_string(((insn & 0xf00) >> 0x8)) }
            },
            {
                SHOper(OpType::IMM, SHReg::InvalidReg, (insn & 0xff), false, false, false, 0, 1),
                SHOper(OpType::REG, SHReg(R0 + ((insn & 0xf00) >> 0x8)), 0, false, false, false, 0, 4)
            },
            false,
            2,
            addr
        );
    }

    if ((insn & 0xff00) == 0xc700) {
        return SHInsn(
            SHOpCode::op_mova,
            {
                {InstructionToken, "mova"},
                {TextToken, " "},
                {TextToken, "@("},
                {PossibleAddressToken, int_to_hex((insn & 0xff))},
                {OperandSeparatorToken, ", "},
                {RegisterToken, "PC"},
                {TextToken, ")"},
                {OperandSeparatorToken, ", "},
                {RegisterToken, "R0"}
            },
            {
                SHOper(OpType::DISP, SHReg::InvalidReg, (insn & 0xff), true, true, false, 0, 1),
                SHOper(OpType::REG, SHReg(PC), 0, false, false, false, 0, 4),
                SHOper(OpType::REG, SHReg(R0), 0, false, false, false, 0, 4)
            },
            false,
            2,
            addr
        );
    }

    if ((insn & 0xf000) == 0x9000) {
        return SHInsn(
            SHOpCode::op_mov_w,
            {
                {InstructionToken, "mov.w"},
                {TextToken, " "},
                {TextToken, "@("},
                {PossibleAddressToken, int_to_hex((insn & 0xff))},
                {OperandSeparatorToken, ", "},
                {RegisterToken, "PC"},
                {TextToken, ")"},
                {OperandSeparatorToken, ", "},
                {RegisterToken, "R" + std::to_string(((insn & 0xf00) >> 0x8)) }
            },
            {
                SHOper(OpType::DISP, SHReg::InvalidReg, (insn & 0xff), true, true, false, 0, 1),
                SHOper(OpType::REG, SHReg(PC), 0, false, false, false, 0, 4),
                SHOper(OpType::REG, SHReg(R0 + ((insn & 0xf00) >> 0x8)), 0, false, false, false, 0, 4)
            },
            false,
            2,
            addr
        );
    }

    if ((insn & 0xf000) == 0xd000) {
        return SHInsn(
            SHOpCode::op_mov_l,
            {
                {InstructionToken, "mov.l"},
                {TextToken, " "},
                {TextToken, "@("},
                {PossibleAddressToken, int_to_hex((insn & 0xff))},
                {OperandSeparatorToken, ", "},
                {RegisterToken, "PC"},
                {TextToken, ")"},
                {OperandSeparatorToken, ", "},
                {RegisterToken, "R" + std::to_string(((insn & 0xf00) >> 0x8)) }
            },
            {
                SHOper(OpType::DISP, SHReg::InvalidReg, (insn & 0xff), true, true, false, 0, 1),
                SHOper(OpType::REG, SHReg(PC), 0, false, false, false, 0, 4),
                SHOper(OpType::REG, SHReg(R0 + ((insn & 0xf00) >> 0x8)), 0, false, false, false, 0, 4)
            },
            false,
            2,
            addr
        );
    }

    if ((insn & 0xf00f) == 0x6000) {
        return SHInsn(
            SHOpCode::op_mov_b,
            {
                {InstructionToken, "mov.b"},
                {TextToken, " "},
                {TextToken, "@"},
                {RegisterToken, "R" + std::to_string(((insn & 0xf0) >> 0x4)) },
                {OperandSeparatorToken, ", "},
                {RegisterToken, "R" + std::to_string(((insn & 0xf00) >> 0x8)) }
            },
            {
                SHOper(OpType::REG, SHReg(R0 + ((insn & 0xf0) >> 0x4)), 0, true, false, false, 0, 4),
                SHOper(OpType::REG, SHReg(R0 + ((insn & 0xf00) >> 0x8)), 0, false, false, false, 0, 4)
            },
            false,
            2,
            addr
        );
    }

    if ((insn & 0xf00f) == 0x6001) {
        return SHInsn(
            SHOpCode::op_mov_w,
            {
                {InstructionToken, "mov.w"},
                {TextToken, " "},
                {TextToken, "@"},
                {RegisterToken, "R" + std::to_string(((insn & 0xf0) >> 0x4)) },
                {OperandSeparatorToken, ", "},
                {RegisterToken, "R" + std::to_string(((insn & 0xf00) >> 0x8)) }
            },
            {
                SHOper(OpType::REG, SHReg(R0 + ((insn & 0xf0) >> 0x4)), 0, true, false, false, 0, 4),
                SHOper(OpType::REG, SHReg(R0 + ((insn & 0xf00) >> 0x8)), 0, false, false, false, 0, 4)
            },
            false,
            2,
            addr
        );
    }

    if ((insn & 0xf00f) == 0x6002) {
        return SHInsn(
            SHOpCode::op_mov_l,
            {
                {InstructionToken, "mov.l"},
                {TextToken, " "},
                {TextToken, "@"},
                {RegisterToken, "R" + std::to_string(((insn & 0xf0) >> 0x4)) },
                {OperandSeparatorToken, ", "},
                {RegisterToken, "R" + std::to_string(((insn & 0xf00) >> 0x8)) }
            },
            {
                SHOper(OpType::REG, SHReg(R0 + ((insn & 0xf0) >> 0x4)), 0, true, false, false, 0, 4),
                SHOper(OpType::REG, SHReg(R0 + ((insn & 0xf00) >> 0x8)), 0, false, false, false, 0, 4)
            },
            false,
            2,
            addr
        );
    }

    if ((insn & 0xf00f) == 0x2000) {
        return SHInsn(
            SHOpCode::op_mov_b,
            {
                {InstructionToken, "mov.b"},
                {TextToken, " "},
                {RegisterToken, "R" + std::to_string(((insn & 0xf0) >> 0x4)) },
                {OperandSeparatorToken, ", "},
                {TextToken, "@"},
                {RegisterToken, "R" + std::to_string(((insn & 0xf00) >> 0x8)) }
            },
            {
                SHOper(OpType::REG, SHReg(R0 + ((insn & 0xf0) >> 0x4)), 0, false, false, false, 0, 4),
                SHOper(OpType::REG, SHReg(R0 + ((insn & 0xf00) >> 0x8)), 0, true, false, false, 0, 4)
            },
            false,
            2,
            addr
        );
    }

    if ((insn & 0xf00f) == 0x2001) {
        return SHInsn(
            SHOpCode::op_mov_w,
            {
                {InstructionToken, "mov.w"},
                {TextToken, " "},
                {RegisterToken, "R" + std::to_string(((insn & 0xf0) >> 0x4)) },
                {OperandSeparatorToken, ", "},
                {TextToken, "@"},
                {RegisterToken, "R" + std::to_string(((insn & 0xf00) >> 0x8)) }
            },
            {
                SHOper(OpType::REG, SHReg(R0 + ((insn & 0xf0) >> 0x4)), 0, false, false, false, 0, 4),
                SHOper(OpType::REG, SHReg(R0 + ((insn & 0xf00) >> 0x8)), 0, true, false, false, 0, 4)
            },
            false,
            2,
            addr
        );
    }

    if ((insn & 0xf00f) == 0x2002) {
        return SHInsn(
            SHOpCode::op_mov_l,
            {
                {InstructionToken, "mov.l"},
                {TextToken, " "},
                {RegisterToken, "R" + std::to_string(((insn & 0xf0) >> 0x4)) },
                {OperandSeparatorToken, ", "},
                {TextToken, "@"},
                {RegisterToken, "R" + std::to_string(((insn & 0xf00) >> 0x8)) }
            },
            {
                SHOper(OpType::REG, SHReg(R0 + ((insn & 0xf0) >> 0x4)), 0, false, false, false, 0, 4),
                SHOper(OpType::REG, SHReg(R0 + ((insn & 0xf00) >> 0x8)), 0, true, false, false, 0, 4)
            },
            false,
            2,
            addr
        );
    }

    if ((insn & 0xf00f) == 0x6004) {
        return SHInsn(
            SHOpCode::op_mov_b,
            {
                {InstructionToken, "mov.b"},
                {TextToken, " "},
                {TextToken, "@"},
                {RegisterToken, "R" + std::to_string(((insn & 0xf0) >> 0x4)) },
                {TextToken, "+"},
                {OperandSeparatorToken, ", "},
                {RegisterToken, "R" + std::to_string(((insn & 0xf00) >> 0x8)) }
            },
            {
                SHOper(OpType::REG, SHReg(R0 + ((insn & 0xf0) >> 0x4)), 0, true, false, false, 1, 4),
                SHOper(OpType::REG, SHReg(R0 + ((insn & 0xf00) >> 0x8)), 0, false, false, false, 0, 4)
            },
            false,
            2,
            addr
        );
    }

    if ((insn & 0xf00f) == 0x6005) {
        return SHInsn(
            SHOpCode::op_mov_w,
            {
                {InstructionToken, "mov.w"},
                {TextToken, " "},
                {TextToken, "@"},
                {RegisterToken, "R" + std::to_string(((insn & 0xf0) >> 0x4)) },
                {TextToken, "+"},
                {OperandSeparatorToken, ", "},
                {RegisterToken, "R" + std::to_string(((insn & 0xf00) >> 0x8)) }
            },
            {
                SHOper(OpType::REG, SHReg(R0 + ((insn & 0xf0) >> 0x4)), 0, true, false, false, 2, 4),
                SHOper(OpType::REG, SHReg(R0 + ((insn & 0xf00) >> 0x8)), 0, false, false, false, 0, 4)
            },
            false,
            2,
            addr
        );
    }

    if ((insn & 0xf00f) == 0x6006) {
        return SHInsn(
            SHOpCode::op_mov_l,
            {
                {InstructionToken, "mov.l"},
                {TextToken, " "},
                {TextToken, "@"},
                {RegisterToken, "R" + std::to_string(((insn & 0xf0) >> 0x4)) },
                {TextToken, "+"},
                {OperandSeparatorToken, ", "},
                {RegisterToken, "R" + std::to_string(((insn & 0xf00) >> 0x8)) }
            },
            {
                SHOper(OpType::REG, SHReg(R0 + ((insn & 0xf0) >> 0x4)), 0, true, false, false, 4, 4),
                SHOper(OpType::REG, SHReg(R0 + ((insn & 0xf00) >> 0x8)), 0, false, false, false, 0, 4)
            },
            false,
            2,
            addr
        );
    }

    if ((insn & 0xf00f) == 0x2004) {
        return SHInsn(
            SHOpCode::op_mov_b,
            {
                {InstructionToken, "mov.b"},
                {TextToken, " "},
                {RegisterToken, "R" + std::to_string(((insn & 0xf0) >> 0x4)) },
                {OperandSeparatorToken, ", "},
                {TextToken, "@-"},
                {RegisterToken, "R" + std::to_string(((insn & 0xf00) >> 0x8)) }
            },
            {
                SHOper(OpType::REG, SHReg(R0 + ((insn & 0xf0) >> 0x4)), 0, false, false, false, 0, 4),
                SHOper(OpType::REG, SHReg(R0 + ((insn & 0xf00) >> 0x8)), 0, true, false, false, -1, 4)
            },
            false,
            2,
            addr
        );
    }

    if ((insn & 0xf00f) == 0x2005) {
        return SHInsn(
            SHOpCode::op_mov_w,
            {
                {InstructionToken, "mov.w"},
                {TextToken, " "},
                {RegisterToken, "R" + std::to_string(((insn & 0xf0) >> 0x4)) },
                {OperandSeparatorToken, ", "},
                {TextToken, "@-"},
                {RegisterToken, "R" + std::to_string(((insn & 0xf00) >> 0x8)) }
            },
            {
                SHOper(OpType::REG, SHReg(R0 + ((insn & 0xf0) >> 0x4)), 0, false, false, false, 0, 4),
                SHOper(OpType::REG, SHReg(R0 + ((insn & 0xf00) >> 0x8)), 0, true, false, false, -2, 4)
            },
            false,
            2,
            addr
        );
    }

    if ((insn & 0xf00f) == 0x2006) {
        return SHInsn(
            SHOpCode::op_mov_l,
            {
                {InstructionToken, "mov.l"},
                {TextToken, " "},
                {RegisterToken, "R" + std::to_string(((insn & 0xf0) >> 0x4)) },
                {OperandSeparatorToken, ", "},
                {TextToken, "@-"},
                {RegisterToken, "R" + std::to_string(((insn & 0xf00) >> 0x8)) }
            },
            {
                SHOper(OpType::REG, SHReg(R0 + ((insn & 0xf0) >> 0x4)), 0, false, false, false, 0, 4),
                SHOper(OpType::REG, SHReg(R0 + ((insn & 0xf00) >> 0x8)), 0, true, false, false, -4, 4)
            },
            false,
            2,
            addr
        );
    }

    if ((insn & 0xf0ff) == 0x40cb) {
        return SHInsn(
            SHOpCode::op_mov_b,
            {
                {InstructionToken, "mov.b"},
                {TextToken, " "},
                {TextToken, "@-"},
                {RegisterToken, "R" + std::to_string(((insn & 0xf00) >> 0x8)) },
                {OperandSeparatorToken, ", "},
                {RegisterToken, "R0"}
            },
            {
                SHOper(OpType::REG, SHReg(R0 + ((insn & 0xf00) >> 0x8)), 0, true, false, false, -1, 4),
                SHOper(OpType::REG, SHReg(R0), 0, false, false, false, 0, 4)
            },
            false,
            2,
            addr
        );
    }

    if ((insn & 0xf0ff) == 0x40db) {
        return SHInsn(
            SHOpCode::op_mov_w,
            {
                {InstructionToken, "mov.w"},
                {TextToken, " "},
                {TextToken, "@-"},
                {RegisterToken, "R" + std::to_string(((insn & 0xf00) >> 0x8)) },
                {OperandSeparatorToken, ", "},
                {RegisterToken, "R0"}
            },
            {
                SHOper(OpType::REG, SHReg(R0 + ((insn & 0xf00) >> 0x8)), 0, true, false, false, -2, 4),
                SHOper(OpType::REG, SHReg(R0), 0, false, false, false, 0, 4)
            },
            false,
            2,
            addr
        );
    }

    if ((insn & 0xf0ff) == 0x40eb) {
        return SHInsn(
            SHOpCode::op_mov_l,
            {
                {InstructionToken, "mov.l"},
                {TextToken, " "},
                {TextToken, "@-"},
                {RegisterToken, "R" + std::to_string(((insn & 0xf00) >> 0x8)) },
                {OperandSeparatorToken, ", "},
                {RegisterToken, "R0"}
            },
            {
                SHOper(OpType::REG, SHReg(R0 + ((insn & 0xf00) >> 0x8)), 0, true, false, false, -4, 4),
                SHOper(OpType::REG, SHReg(R0), 0, false, false, false, 0, 4)
            },
            false,
            2,
            addr
        );
    }

    if ((insn & 0xf0ff) == 0x408b) {
        return SHInsn(
            SHOpCode::op_mov_b,
            {
                {InstructionToken, "mov.b"},
                {TextToken, " "},
                {RegisterToken, "R0"},
                {OperandSeparatorToken, ", "},
                {TextToken, "@"},
                {RegisterToken, "R" + std::to_string(((insn & 0xf00) >> 0x8)) },
                {TextToken, "+"}
            },
            {
                SHOper(OpType::REG, SHReg(R0), 0, false, false, false, 0, 4),
                SHOper(OpType::REG, SHReg(R0 + ((insn & 0xf00) >> 0x8)), 0, true, false, false, 1, 4)
            },
            false,
            2,
            addr
        );
    }

    if ((insn & 0xf0ff) == 0x409b) {
        return SHInsn(
            SHOpCode::op_mov_w,
            {
                {InstructionToken, "mov.w"},
                {TextToken, " "},
                {RegisterToken, "R0"},
                {OperandSeparatorToken, ", "},
                {TextToken, "@"},
                {RegisterToken, "R" + std::to_string(((insn & 0xf00) >> 0x8)) },
                {TextToken, "+"}
            },
            {
                SHOper(OpType::REG, SHReg(R0), 0, false, false, false, 0, 4),
                SHOper(OpType::REG, SHReg(R0 + ((insn & 0xf00) >> 0x8)), 0, true, false, false, 2, 4)
            },
            false,
            2,
            addr
        );
    }

    if ((insn & 0xf0ff) == 0x40ab) {
        return SHInsn(
            SHOpCode::op_mov_l,
            {
                {InstructionToken, "mov.l"},
                {TextToken, " "},
                {RegisterToken, "R0"},
                {OperandSeparatorToken, ", "},
                {TextToken, "@"},
                {RegisterToken, "R" + std::to_string(((insn & 0xf00) >> 0x8)) },
                {TextToken, "+"}
            },
            {
                SHOper(OpType::REG, SHReg(R0), 0, false, false, false, 0, 4),
                SHOper(OpType::REG, SHReg(R0 + ((insn & 0xf00) >> 0x8)), 0, true, false, false, 4, 4)
            },
            false,
            2,
            addr
        );
    }

    if ((insn & 0xff00) == 0x8400) {
        return SHInsn(
            SHOpCode::op_mov_b,
            {
                {InstructionToken, "mov.b"},
                {TextToken, " "},
                {TextToken, "@("},
                {PossibleAddressToken, int_to_hex((insn & 0xf))},
                {OperandSeparatorToken, ", "},
                {RegisterToken, "R" + std::to_string(((insn & 0xf0) >> 0x4)) },
                {TextToken, ")"},
                {OperandSeparatorToken, ", "},
                {RegisterToken, "R0"}
            },
            {
                SHOper(OpType::DISP, SHReg::InvalidReg, (insn & 0xf), true, true, false, 0, 1),
                SHOper(OpType::REG, SHReg(R0 + ((insn & 0xf0) >> 0x4)), 0, false, false, false, 0, 4),
                SHOper(OpType::REG, SHReg(R0), 0, false, false, false, 0, 4)
            },
            false,
            2,
            addr
        );
    }

    if ((insn & 0xff00) == 0x8500) {
        return SHInsn(
            SHOpCode::op_mov_w,
            {
                {InstructionToken, "mov.w"},
                {TextToken, " "},
                {TextToken, "@("},
                {PossibleAddressToken, int_to_hex((insn & 0xf))},
                {OperandSeparatorToken, ", "},
                {RegisterToken, "R" + std::to_string(((insn & 0xf0) >> 0x4)) },
                {TextToken, ")"},
                {OperandSeparatorToken, ", "},
                {RegisterToken, "R0"}
            },
            {
                SHOper(OpType::DISP, SHReg::InvalidReg, (insn & 0xf), true, true, false, 0, 1),
                SHOper(OpType::REG, SHReg(R0 + ((insn & 0xf0) >> 0x4)), 0, false, false, false, 0, 4),
                SHOper(OpType::REG, SHReg(R0), 0, false, false, false, 0, 4)
            },
            false,
            2,
            addr
        );
    }

    if ((insn & 0xf000) == 0x5000) {
        return SHInsn(
            SHOpCode::op_mov_l,
            {
                {InstructionToken, "mov.l"},
                {TextToken, " "},
                {TextToken, "@("},
                {PossibleAddressToken, int_to_hex((insn & 0xf))},
                {OperandSeparatorToken, ", "},
                {RegisterToken, "R" + std::to_string(((insn & 0xf0) >> 0x4)) },
                {TextToken, ")"},
                {OperandSeparatorToken, ", "},
                {RegisterToken, "R" + std::to_string(((insn & 0xf00) >> 0x8)) }
            },
            {
                SHOper(OpType::DISP, SHReg::InvalidReg, (insn & 0xf), true, true, false, 0, 1),
                SHOper(OpType::REG, SHReg(R0 + ((insn & 0xf0) >> 0x4)), 0, false, false, false, 0, 4),
                SHOper(OpType::REG, SHReg(R0 + ((insn & 0xf00) >> 0x8)), 0, false, false, false, 0, 4)
            },
            false,
            2,
            addr
        );
    }

    if ((insn & 0xff00) == 0x8000) {
        return SHInsn(
            SHOpCode::op_mov_b,
            {
                {InstructionToken, "mov.b"},
                {TextToken, " "},
                {RegisterToken, "R0"},
                {OperandSeparatorToken, ", "},
                {TextToken, "@("},
                {PossibleAddressToken, int_to_hex((insn & 0xf))},
                {OperandSeparatorToken, ", "},
                {RegisterToken, "R" + std::to_string(((insn & 0xf0) >> 0x4)) },
                {TextToken, ")"}
            },
            {
                SHOper(OpType::REG, SHReg(R0), 0, false, false, false, 0, 4),
                SHOper(OpType::DISP, SHReg::InvalidReg, (insn & 0xf), true, true, false, 0, 1),
                SHOper(OpType::REG, SHReg(R0 + ((insn & 0xf0) >> 0x4)), 0, false, false, false, 0, 4)
            },
            false,
            2,
            addr
        );
    }

    if ((insn & 0xff00) == 0x8100) {
        return SHInsn(
            SHOpCode::op_mov_w,
            {
                {InstructionToken, "mov.w"},
                {TextToken, " "},
                {RegisterToken, "R0"},
                {OperandSeparatorToken, ", "},
                {TextToken, "@("},
                {PossibleAddressToken, int_to_hex((insn & 0xf))},
                {OperandSeparatorToken, ", "},
                {RegisterToken, "R" + std::to_string(((insn & 0xf0) >> 0x4)) },
                {TextToken, ")"}
            },
            {
                SHOper(OpType::REG, SHReg(R0), 0, false, false, false, 0, 4),
                SHOper(OpType::DISP, SHReg::InvalidReg, (insn & 0xf), true, true, false, 0, 1),
                SHOper(OpType::REG, SHReg(R0 + ((insn & 0xf0) >> 0x4)), 0, false, false, false, 0, 4)
            },
            false,
            2,
            addr
        );
    }

    if ((insn & 0xf000) == 0x1000) {
        return SHInsn(
            SHOpCode::op_mov_l,
            {
                {InstructionToken, "mov.l"},
                {TextToken, " "},
                {RegisterToken, "R" + std::to_string(((insn & 0xf0) >> 0x4)) },
                {OperandSeparatorToken, ", "},
                {TextToken, "@("},
                {PossibleAddressToken, int_to_hex((insn & 0xf))},
                {OperandSeparatorToken, ", "},
                {RegisterToken, "R" + std::to_string(((insn & 0xf00) >> 0x8)) },
                {TextToken, ")"}
            },
            {
                SHOper(OpType::REG, SHReg(R0 + ((insn & 0xf0) >> 0x4)), 0, false, false, false, 0, 4),
                SHOper(OpType::DISP, SHReg::InvalidReg, (insn & 0xf), true, true, false, 0, 1),
                SHOper(OpType::REG, SHReg(R0 + ((insn & 0xf00) >> 0x8)), 0, false, false, false, 0, 4)
            },
            false,
            2,
            addr
        );
    }

    if ((insn & 0xf00f) == 0x000c) {
        return SHInsn(
            SHOpCode::op_mov_b,
            {
                {InstructionToken, "mov.b"},
                {TextToken, " "},
                {TextToken, "@("},
                {RegisterToken, "R0"},
                {OperandSeparatorToken, ", "},
                {RegisterToken, "R" + std::to_string(((insn & 0xf0) >> 0x4)) },
                {TextToken, ")"},
                {OperandSeparatorToken, ", "},
                {RegisterToken, "R" + std::to_string(((insn & 0xf00) >> 0x8)) }
            },
            {
                SHOper(OpType::REG, SHReg(R0), 0, true, true, false, 0, 4),
                SHOper(OpType::REG, SHReg(R0 + ((insn & 0xf0) >> 0x4)), 0, false, false, false, 0, 4),
                SHOper(OpType::REG, SHReg(R0 + ((insn & 0xf00) >> 0x8)), 0, false, false, false, 0, 4)
            },
            false,
            2,
            addr
        );
    }

    if ((insn & 0xf00f) == 0x000d) {
        return SHInsn(
            SHOpCode::op_mov_w,
            {
                {InstructionToken, "mov.w"},
                {TextToken, " "},
                {TextToken, "@("},
                {RegisterToken, "R0"},
                {OperandSeparatorToken, ", "},
                {RegisterToken, "R" + std::to_string(((insn & 0xf0) >> 0x4)) },
                {TextToken, ")"},
                {OperandSeparatorToken, ", "},
                {RegisterToken, "R" + std::to_string(((insn & 0xf00) >> 0x8)) }
            },
            {
                SHOper(OpType::REG, SHReg(R0), 0, true, true, false, 0, 4),
                SHOper(OpType::REG, SHReg(R0 + ((insn & 0xf0) >> 0x4)), 0, false, false, false, 0, 4),
                SHOper(OpType::REG, SHReg(R0 + ((insn & 0xf00) >> 0x8)), 0, false, false, false, 0, 4)
            },
            false,
            2,
            addr
        );
    }

    if ((insn & 0xf00f) == 0x000e) {
        return SHInsn(
            SHOpCode::op_mov_l,
            {
                {InstructionToken, "mov.l"},
                {TextToken, " "},
                {TextToken, "@("},
                {RegisterToken, "R0"},
                {OperandSeparatorToken, ", "},
                {RegisterToken, "R" + std::to_string(((insn & 0xf0) >> 0x4)) },
                {TextToken, ")"},
                {OperandSeparatorToken, ", "},
                {RegisterToken, "R" + std::to_string(((insn & 0xf00) >> 0x8)) }
            },
            {
                SHOper(OpType::REG, SHReg(R0), 0, true, true, false, 0, 4),
                SHOper(OpType::REG, SHReg(R0 + ((insn & 0xf0) >> 0x4)), 0, false, false, false, 0, 4),
                SHOper(OpType::REG, SHReg(R0 + ((insn & 0xf00) >> 0x8)), 0, false, false, false, 0, 4)
            },
            false,
            2,
            addr
        );
    }

    if ((insn & 0xf00f) == 0x0004) {
        return SHInsn(
            SHOpCode::op_mov_b,
            {
                {InstructionToken, "mov.b"},
                {TextToken, " "},
                {RegisterToken, "R" + std::to_string(((insn & 0xf0) >> 0x4)) },
                {OperandSeparatorToken, ", "},
                {TextToken, "@("},
                {RegisterToken, "R0"},
                {OperandSeparatorToken, ", "},
                {RegisterToken, "R" + std::to_string(((insn & 0xf00) >> 0x8)) },
                {TextToken, ")"}
            },
            {
                SHOper(OpType::REG, SHReg(R0 + ((insn & 0xf0) >> 0x4)), 0, false, false, false, 0, 4),
                SHOper(OpType::REG, SHReg(R0), 0, true, true, false, 0, 4),
                SHOper(OpType::REG, SHReg(R0 + ((insn & 0xf00) >> 0x8)), 0, false, false, false, 0, 4)
            },
            false,
            2,
            addr
        );
    }

    if ((insn & 0xf00f) == 0x0005) {
        return SHInsn(
            SHOpCode::op_mov_w,
            {
                {InstructionToken, "mov.w"},
                {TextToken, " "},
                {RegisterToken, "R" + std::to_string(((insn & 0xf0) >> 0x4)) },
                {OperandSeparatorToken, ", "},
                {TextToken, "@("},
                {RegisterToken, "R0"},
                {OperandSeparatorToken, ", "},
                {RegisterToken, "R" + std::to_string(((insn & 0xf00) >> 0x8)) },
                {TextToken, ")"}
            },
            {
                SHOper(OpType::REG, SHReg(R0 + ((insn & 0xf0) >> 0x4)), 0, false, false, false, 0, 4),
                SHOper(OpType::REG, SHReg(R0), 0, true, true, false, 0, 4),
                SHOper(OpType::REG, SHReg(R0 + ((insn & 0xf00) >> 0x8)), 0, false, false, false, 0, 4)
            },
            false,
            2,
            addr
        );
    }

    if ((insn & 0xf00f) == 0x0006) {
        return SHInsn(
            SHOpCode::op_mov_l,
            {
                {InstructionToken, "mov.l"},
                {TextToken, " "},
                {RegisterToken, "R" + std::to_string(((insn & 0xf0) >> 0x4)) },
                {OperandSeparatorToken, ", "},
                {TextToken, "@("},
                {RegisterToken, "R0"},
                {OperandSeparatorToken, ", "},
                {RegisterToken, "R" + std::to_string(((insn & 0xf00) >> 0x8)) },
                {TextToken, ")"}
            },
            {
                SHOper(OpType::REG, SHReg(R0 + ((insn & 0xf0) >> 0x4)), 0, false, false, false, 0, 4),
                SHOper(OpType::REG, SHReg(R0), 0, true, true, false, 0, 4),
                SHOper(OpType::REG, SHReg(R0 + ((insn & 0xf00) >> 0x8)), 0, false, false, false, 0, 4)
            },
            false,
            2,
            addr
        );
    }

    if ((insn & 0xff00) == 0xc400) {
        return SHInsn(
            SHOpCode::op_mov_b,
            {
                {InstructionToken, "mov.b"},
                {TextToken, " "},
                {TextToken, "@("},
                {PossibleAddressToken, int_to_hex((insn & 0xff))},
                {OperandSeparatorToken, ", "},
                {RegisterToken, "GBR"},
                {TextToken, ")"},
                {OperandSeparatorToken, ", "},
                {RegisterToken, "R0"}
            },
            {
                SHOper(OpType::DISP, SHReg::InvalidReg, (insn & 0xff), true, true, false, 0, 1),
                SHOper(OpType::REG, SHReg(GBR), 0, false, false, false, 0, 4),
                SHOper(OpType::REG, SHReg(R0), 0, false, false, false, 0, 4)
            },
            false,
            2,
            addr
        );
    }

    if ((insn & 0xff00) == 0xc500) {
        return SHInsn(
            SHOpCode::op_mov_w,
            {
                {InstructionToken, "mov.w"},
                {TextToken, " "},
                {TextToken, "@("},
                {PossibleAddressToken, int_to_hex((insn & 0xff))},
                {OperandSeparatorToken, ", "},
                {RegisterToken, "GBR"},
                {TextToken, ")"},
                {OperandSeparatorToken, ", "},
                {RegisterToken, "R0"}
            },
            {
                SHOper(OpType::DISP, SHReg::InvalidReg, (insn & 0xff), true, true, false, 0, 1),
                SHOper(OpType::REG, SHReg(GBR), 0, false, false, false, 0, 4),
                SHOper(OpType::REG, SHReg(R0), 0, false, false, false, 0, 4)
            },
            false,
            2,
            addr
        );
    }

    if ((insn & 0xff00) == 0xc600) {
        return SHInsn(
            SHOpCode::op_mov_l,
            {
                {InstructionToken, "mov.l"},
                {TextToken, " "},
                {TextToken, "@("},
                {PossibleAddressToken, int_to_hex((insn & 0xff))},
                {OperandSeparatorToken, ", "},
                {RegisterToken, "GBR"},
                {TextToken, ")"},
                {OperandSeparatorToken, ", "},
                {RegisterToken, "R0"}
            },
            {
                SHOper(OpType::DISP, SHReg::InvalidReg, (insn & 0xff), true, true, false, 0, 1),
                SHOper(OpType::REG, SHReg(GBR), 0, false, false, false, 0, 4),
                SHOper(OpType::REG, SHReg(R0), 0, false, false, false, 0, 4)
            },
            false,
            2,
            addr
        );
    }

    if ((insn & 0xff00) == 0xc000) {
        return SHInsn(
            SHOpCode::op_mov_b,
            {
                {InstructionToken, "mov.b"},
                {TextToken, " "},
                {RegisterToken, "R0"},
                {OperandSeparatorToken, ", "},
                {TextToken, "@("},
                {PossibleAddressToken, int_to_hex((insn & 0xff))},
                {OperandSeparatorToken, ", "},
                {RegisterToken, "GBR"},
                {TextToken, ")"}
            },
            {
                SHOper(OpType::REG, SHReg(R0), 0, false, false, false, 0, 4),
                SHOper(OpType::DISP, SHReg::InvalidReg, (insn & 0xff), true, true, false, 0, 1),
                SHOper(OpType::REG, SHReg(GBR), 0, false, false, false, 0, 4)
            },
            false,
            2,
            addr
        );
    }

    if ((insn & 0xff00) == 0xc100) {
        return SHInsn(
            SHOpCode::op_mov_w,
            {
                {InstructionToken, "mov.w"},
                {TextToken, " "},
                {RegisterToken, "R0"},
                {OperandSeparatorToken, ", "},
                {TextToken, "@("},
                {PossibleAddressToken, int_to_hex((insn & 0xff))},
                {OperandSeparatorToken, ", "},
                {RegisterToken, "GBR"},
                {TextToken, ")"}
            },
            {
                SHOper(OpType::REG, SHReg(R0), 0, false, false, false, 0, 4),
                SHOper(OpType::DISP, SHReg::InvalidReg, (insn & 0xff), true, true, false, 0, 1),
                SHOper(OpType::REG, SHReg(GBR), 0, false, false, false, 0, 4)
            },
            false,
            2,
            addr
        );
    }

    if ((insn & 0xff00) == 0xc200) {
        return SHInsn(
            SHOpCode::op_mov_l,
            {
                {InstructionToken, "mov.l"},
                {TextToken, " "},
                {RegisterToken, "R0"},
                {OperandSeparatorToken, ", "},
                {TextToken, "@("},
                {PossibleAddressToken, int_to_hex((insn & 0xff))},
                {OperandSeparatorToken, ", "},
                {RegisterToken, "GBR"},
                {TextToken, ")"}
            },
            {
                SHOper(OpType::REG, SHReg(R0), 0, false, false, false, 0, 4),
                SHOper(OpType::DISP, SHReg::InvalidReg, (insn & 0xff), true, true, false, 0, 1),
                SHOper(OpType::REG, SHReg(GBR), 0, false, false, false, 0, 4)
            },
            false,
            2,
            addr
        );
    }

    if ((insn & 0xf0ff) == 0x0073) {
        return SHInsn(
            SHOpCode::op_movco_l,
            {
                {InstructionToken, "movco.l"},
                {TextToken, " "},
                {RegisterToken, "R0"},
                {OperandSeparatorToken, ", "},
                {TextToken, "@"},
                {RegisterToken, "R" + std::to_string(((insn & 0xf00) >> 0x8)) }
            },
            {
                SHOper(OpType::REG, SHReg(R0), 0, false, false, false, 0, 4),
                SHOper(OpType::REG, SHReg(R0 + ((insn & 0xf00) >> 0x8)), 0, true, false, false, 0, 4)
            },
            false,
            2,
            addr
        );
    }

    if ((insn & 0xf0ff) == 0x0063) {
        return SHInsn(
            SHOpCode::op_movli_l,
            {
                {InstructionToken, "movli.l"},
                {TextToken, " "},
                {TextToken, "@"},
                {RegisterToken, "R" + std::to_string(((insn & 0xf00) >> 0x8)) },
                {OperandSeparatorToken, ", "},
                {RegisterToken, "R0"}
            },
            {
                SHOper(OpType::REG, SHReg(R0 + ((insn & 0xf00) >> 0x8)), 0, true, false, false, 0, 4),
                SHOper(OpType::REG, SHReg(R0), 0, false, false, false, 0, 4)
            },
            false,
            2,
            addr
        );
    }

    if ((insn & 0xf0ff) == 0x40a9) {
        return SHInsn(
            SHOpCode::op_movua_l,
            {
                {InstructionToken, "movua.l"},
                {TextToken, " "},
                {TextToken, "@"},
                {RegisterToken, "R" + std::to_string(((insn & 0xf00) >> 0x8)) },
                {OperandSeparatorToken, ", "},
                {RegisterToken, "R0"}
            },
            {
                SHOper(OpType::REG, SHReg(R0 + ((insn & 0xf00) >> 0x8)), 0, true, false, false, 0, 4),
                SHOper(OpType::REG, SHReg(R0), 0, false, false, false, 0, 4)
            },
            false,
            2,
            addr
        );
    }

    if ((insn & 0xf0ff) == 0x40e9) {
        return SHInsn(
            SHOpCode::op_movua_l,
            {
                {InstructionToken, "movua.l"},
                {TextToken, " "},
                {TextToken, "@"},
                {RegisterToken, "R" + std::to_string(((insn & 0xf00) >> 0x8)) },
                {TextToken, "+"},
                {OperandSeparatorToken, ", "},
                {RegisterToken, "R0"}
            },
            {
                SHOper(OpType::REG, SHReg(R0 + ((insn & 0xf00) >> 0x8)), 0, true, false, false, 4, 4),
                SHOper(OpType::REG, SHReg(R0), 0, false, false, false, 0, 4)
            },
            false,
            2,
            addr
        );
    }

    if ((insn & 0xf0ff) == 0x40f1) {
        return SHInsn(
            SHOpCode::op_movml_l,
            {
                {InstructionToken, "movml.l"},
                {TextToken, " "},
                {RegisterToken, "R" + std::to_string(((insn & 0xf00) >> 0x8)) },
                {OperandSeparatorToken, ", "},
                {TextToken, "@-"},
                {RegisterToken, "R15"}
            },
            {
                SHOper(OpType::REG, SHReg(R0 + ((insn & 0xf00) >> 0x8)), 0, false, false, false, 0, 4),
                SHOper(OpType::REG, SHReg(R15), 0, true, false, false, -4, 4)
            },
            false,
            2,
            addr
        );
    }

    if ((insn & 0xf0ff) == 0x40f5) {
        return SHInsn(
            SHOpCode::op_movml_l,
            {
                {InstructionToken, "movml.l"},
                {TextToken, " "},
                {TextToken, "@"},
                {RegisterToken, "R15"},
                {TextToken, "+"},
                {OperandSeparatorToken, ", "},
                {RegisterToken, "R" + std::to_string(((insn & 0xf00) >> 0x8)) }
            },
            {
                SHOper(OpType::REG, SHReg(R15), 0, true, false, false, 4, 4),
                SHOper(OpType::REG, SHReg(R0 + ((insn & 0xf00) >> 0x8)), 0, false, false, false, 0, 4)
            },
            false,
            2,
            addr
        );
    }

    if ((insn & 0xf0ff) == 0x40f0) {
        return SHInsn(
            SHOpCode::op_movmu_l,
            {
                {InstructionToken, "movmu.l"},
                {TextToken, " "},
                {RegisterToken, "R" + std::to_string(((insn & 0xf00) >> 0x8)) },
                {OperandSeparatorToken, ", "},
                {TextToken, "@-"},
                {RegisterToken, "R15"}
            },
            {
                SHOper(OpType::REG, SHReg(R0 + ((insn & 0xf00) >> 0x8)), 0, false, false, false, 0, 4),
                SHOper(OpType::REG, SHReg(R15), 0, true, false, false, -4, 4)
            },
            false,
            2,
            addr
        );
    }

    if ((insn & 0xf0ff) == 0x40f4) {
        return SHInsn(
            SHOpCode::op_movmu_l,
            {
                {InstructionToken, "movmu.l"},
                {TextToken, " "},
                {TextToken, "@"},
                {RegisterToken, "R15"},
                {TextToken, "+"},
                {OperandSeparatorToken, ", "},
                {RegisterToken, "R" + std::to_string(((insn & 0xf00) >> 0x8)) }
            },
            {
                SHOper(OpType::REG, SHReg(R15), 0, true, false, false, 4, 4),
                SHOper(OpType::REG, SHReg(R0 + ((insn & 0xf00) >> 0x8)), 0, false, false, false, 0, 4)
            },
            false,
            2,
            addr
        );
    }

    if ((insn & 0xf0ff) == 0x0039) {
        return SHInsn(
            SHOpCode::op_movrt,
            {
                {InstructionToken, "movrt"},
                {TextToken, " "},
                {RegisterToken, "R" + std::to_string(((insn & 0xf00) >> 0x8)) }
            },
            {
                SHOper(OpType::REG, SHReg(R0 + ((insn & 0xf00) >> 0x8)), 0, false, false, false, 0, 4)
            },
            false,
            2,
            addr
        );
    }

    if ((insn & 0xf0ff) == 0x0029) {
        return SHInsn(
            SHOpCode::op_movt,
            {
                {InstructionToken, "movt"},
                {TextToken, " "},
                {RegisterToken, "R" + std::to_string(((insn & 0xf00) >> 0x8)) }
            },
            {
                SHOper(OpType::REG, SHReg(R0 + ((insn & 0xf00) >> 0x8)), 0, false, false, false, 0, 4)
            },
            false,
            2,
            addr
        );
    }

    if ((insn & 0xffff) == 0x0068) {
        return SHInsn(
            SHOpCode::op_nott,
            {
                {InstructionToken, "nott"},
                {TextToken, " "}
            },
            {
                
            },
            false,
            2,
            addr
        );
    }

    if ((insn & 0xf00f) == 0x6008) {
        return SHInsn(
            SHOpCode::op_swap_b,
            {
                {InstructionToken, "swap.b"},
                {TextToken, " "},
                {RegisterToken, "R" + std::to_string(((insn & 0xf0) >> 0x4)) },
                {OperandSeparatorToken, ", "},
                {RegisterToken, "R" + std::to_string(((insn & 0xf00) >> 0x8)) }
            },
            {
                SHOper(OpType::REG, SHReg(R0 + ((insn & 0xf0) >> 0x4)), 0, false, false, false, 0, 4),
                SHOper(OpType::REG, SHReg(R0 + ((insn & 0xf00) >> 0x8)), 0, false, false, false, 0, 4)
            },
            false,
            2,
            addr
        );
    }

    if ((insn & 0xf00f) == 0x6009) {
        return SHInsn(
            SHOpCode::op_swap_w,
            {
                {InstructionToken, "swap.w"},
                {TextToken, " "},
                {RegisterToken, "R" + std::to_string(((insn & 0xf0) >> 0x4)) },
                {OperandSeparatorToken, ", "},
                {RegisterToken, "R" + std::to_string(((insn & 0xf00) >> 0x8)) }
            },
            {
                SHOper(OpType::REG, SHReg(R0 + ((insn & 0xf0) >> 0x4)), 0, false, false, false, 0, 4),
                SHOper(OpType::REG, SHReg(R0 + ((insn & 0xf00) >> 0x8)), 0, false, false, false, 0, 4)
            },
            false,
            2,
            addr
        );
    }

    if ((insn & 0xf00f) == 0x200d) {
        return SHInsn(
            SHOpCode::op_xtrct,
            {
                {InstructionToken, "xtrct"},
                {TextToken, " "},
                {RegisterToken, "R" + std::to_string(((insn & 0xf0) >> 0x4)) },
                {OperandSeparatorToken, ", "},
                {RegisterToken, "R" + std::to_string(((insn & 0xf00) >> 0x8)) }
            },
            {
                SHOper(OpType::REG, SHReg(R0 + ((insn & 0xf0) >> 0x4)), 0, false, false, false, 0, 4),
                SHOper(OpType::REG, SHReg(R0 + ((insn & 0xf00) >> 0x8)), 0, false, false, false, 0, 4)
            },
            false,
            2,
            addr
        );
    }

    if ((insn & 0xff0f) == 0x8600) {
        return SHInsn(
            SHOpCode::op_bclr,
            {
                {InstructionToken, "bclr"},
                {TextToken, " "},
                {PossibleAddressToken, int_to_hex((insn & 0x7))},
                {OperandSeparatorToken, ", "},
                {RegisterToken, "R" + std::to_string(((insn & 0xf0) >> 0x4)) }
            },
            {
                SHOper(OpType::IMM, SHReg::InvalidReg, (insn & 0x7), false, false, false, 0, 1),
                SHOper(OpType::REG, SHReg(R0 + ((insn & 0xf0) >> 0x4)), 0, false, false, false, 0, 4)
            },
            false,
            2,
            addr
        );
    }

    if ((insn & 0xff0f) == 0x8708) {
        return SHInsn(
            SHOpCode::op_bld,
            {
                {InstructionToken, "bld"},
                {TextToken, " "},
                {PossibleAddressToken, int_to_hex((insn & 0x7))},
                {OperandSeparatorToken, ", "},
                {RegisterToken, "R" + std::to_string(((insn & 0xf0) >> 0x4)) }
            },
            {
                SHOper(OpType::IMM, SHReg::InvalidReg, (insn & 0x7), false, false, false, 0, 1),
                SHOper(OpType::REG, SHReg(R0 + ((insn & 0xf0) >> 0x4)), 0, false, false, false, 0, 4)
            },
            false,
            2,
            addr
        );
    }

    if ((insn & 0xff0f) == 0x8608) {
        return SHInsn(
            SHOpCode::op_bset,
            {
                {InstructionToken, "bset"},
                {TextToken, " "},
                {PossibleAddressToken, int_to_hex((insn & 0x7))},
                {OperandSeparatorToken, ", "},
                {RegisterToken, "R" + std::to_string(((insn & 0xf0) >> 0x4)) }
            },
            {
                SHOper(OpType::IMM, SHReg::InvalidReg, (insn & 0x7), false, false, false, 0, 1),
                SHOper(OpType::REG, SHReg(R0 + ((insn & 0xf0) >> 0x4)), 0, false, false, false, 0, 4)
            },
            false,
            2,
            addr
        );
    }

    if ((insn & 0xff0f) == 0x8700) {
        return SHInsn(
            SHOpCode::op_bst,
            {
                {InstructionToken, "bst"},
                {TextToken, " "},
                {PossibleAddressToken, int_to_hex((insn & 0x7))},
                {OperandSeparatorToken, ", "},
                {RegisterToken, "R" + std::to_string(((insn & 0xf0) >> 0x4)) }
            },
            {
                SHOper(OpType::IMM, SHReg::InvalidReg, (insn & 0x7), false, false, false, 0, 1),
                SHOper(OpType::REG, SHReg(R0 + ((insn & 0xf0) >> 0x4)), 0, false, false, false, 0, 4)
            },
            false,
            2,
            addr
        );
    }

    if ((insn & 0xf00f) == 0x300c) {
        return SHInsn(
            SHOpCode::op_add,
            {
                {InstructionToken, "add"},
                {TextToken, " "},
                {RegisterToken, "R" + std::to_string(((insn & 0xf0) >> 0x4)) },
                {OperandSeparatorToken, ", "},
                {RegisterToken, "R" + std::to_string(((insn & 0xf00) >> 0x8)) }
            },
            {
                SHOper(OpType::REG, SHReg(R0 + ((insn & 0xf0) >> 0x4)), 0, false, false, false, 0, 4),
                SHOper(OpType::REG, SHReg(R0 + ((insn & 0xf00) >> 0x8)), 0, false, false, false, 0, 4)
            },
            false,
            2,
            addr
        );
    }

    if ((insn & 0xf000) == 0x7000) {
        return SHInsn(
            SHOpCode::op_add,
            {
                {InstructionToken, "add"},
                {TextToken, " "},
                {PossibleAddressToken, int_to_hex((insn & 0xff))},
                {OperandSeparatorToken, ", "},
                {RegisterToken, "R" + std::to_string(((insn & 0xf00) >> 0x8)) }
            },
            {
                SHOper(OpType::IMM, SHReg::InvalidReg, (insn & 0xff), false, false, false, 0, 1),
                SHOper(OpType::REG, SHReg(R0 + ((insn & 0xf00) >> 0x8)), 0, false, false, false, 0, 4)
            },
            false,
            2,
            addr
        );
    }

    if ((insn & 0xf00f) == 0x300e) {
        return SHInsn(
            SHOpCode::op_addc,
            {
                {InstructionToken, "addc"},
                {TextToken, " "},
                {RegisterToken, "R" + std::to_string(((insn & 0xf0) >> 0x4)) },
                {OperandSeparatorToken, ", "},
                {RegisterToken, "R" + std::to_string(((insn & 0xf00) >> 0x8)) }
            },
            {
                SHOper(OpType::REG, SHReg(R0 + ((insn & 0xf0) >> 0x4)), 0, false, false, false, 0, 4),
                SHOper(OpType::REG, SHReg(R0 + ((insn & 0xf00) >> 0x8)), 0, false, false, false, 0, 4)
            },
            false,
            2,
            addr
        );
    }

    if ((insn & 0xf00f) == 0x300f) {
        return SHInsn(
            SHOpCode::op_addv,
            {
                {InstructionToken, "addv"},
                {TextToken, " "},
                {RegisterToken, "R" + std::to_string(((insn & 0xf0) >> 0x4)) },
                {OperandSeparatorToken, ", "},
                {RegisterToken, "R" + std::to_string(((insn & 0xf00) >> 0x8)) }
            },
            {
                SHOper(OpType::REG, SHReg(R0 + ((insn & 0xf0) >> 0x4)), 0, false, false, false, 0, 4),
                SHOper(OpType::REG, SHReg(R0 + ((insn & 0xf00) >> 0x8)), 0, false, false, false, 0, 4)
            },
            false,
            2,
            addr
        );
    }

    if ((insn & 0xff00) == 0x8800) {
        return SHInsn(
            SHOpCode::op_cmp_eq,
            {
                {InstructionToken, "cmp/eq"},
                {TextToken, " "},
                {PossibleAddressToken, int_to_hex((insn & 0xff))},
                {OperandSeparatorToken, ", "},
                {RegisterToken, "R0"}
            },
            {
                SHOper(OpType::IMM, SHReg::InvalidReg, (insn & 0xff), false, false, false, 0, 1),
                SHOper(OpType::REG, SHReg(R0), 0, false, false, false, 0, 4)
            },
            false,
            2,
            addr
        );
    }

    if ((insn & 0xf00f) == 0x3000) {
        return SHInsn(
            SHOpCode::op_cmp_eq,
            {
                {InstructionToken, "cmp/eq"},
                {TextToken, " "},
                {RegisterToken, "R" + std::to_string(((insn & 0xf0) >> 0x4)) },
                {OperandSeparatorToken, ", "},
                {RegisterToken, "R" + std::to_string(((insn & 0xf00) >> 0x8)) }
            },
            {
                SHOper(OpType::REG, SHReg(R0 + ((insn & 0xf0) >> 0x4)), 0, false, false, false, 0, 4),
                SHOper(OpType::REG, SHReg(R0 + ((insn & 0xf00) >> 0x8)), 0, false, false, false, 0, 4)
            },
            false,
            2,
            addr
        );
    }

    if ((insn & 0xf00f) == 0x3002) {
        return SHInsn(
            SHOpCode::op_cmp_hs,
            {
                {InstructionToken, "cmp/hs"},
                {TextToken, " "},
                {RegisterToken, "R" + std::to_string(((insn & 0xf0) >> 0x4)) },
                {OperandSeparatorToken, ", "},
                {RegisterToken, "R" + std::to_string(((insn & 0xf00) >> 0x8)) }
            },
            {
                SHOper(OpType::REG, SHReg(R0 + ((insn & 0xf0) >> 0x4)), 0, false, false, false, 0, 4),
                SHOper(OpType::REG, SHReg(R0 + ((insn & 0xf00) >> 0x8)), 0, false, false, false, 0, 4)
            },
            false,
            2,
            addr
        );
    }

    if ((insn & 0xf00f) == 0x3003) {
        return SHInsn(
            SHOpCode::op_cmp_ge,
            {
                {InstructionToken, "cmp/ge"},
                {TextToken, " "},
                {RegisterToken, "R" + std::to_string(((insn & 0xf0) >> 0x4)) },
                {OperandSeparatorToken, ", "},
                {RegisterToken, "R" + std::to_string(((insn & 0xf00) >> 0x8)) }
            },
            {
                SHOper(OpType::REG, SHReg(R0 + ((insn & 0xf0) >> 0x4)), 0, false, false, false, 0, 4),
                SHOper(OpType::REG, SHReg(R0 + ((insn & 0xf00) >> 0x8)), 0, false, false, false, 0, 4)
            },
            false,
            2,
            addr
        );
    }

    if ((insn & 0xf00f) == 0x3006) {
        return SHInsn(
            SHOpCode::op_cmp_hi,
            {
                {InstructionToken, "cmp/hi"},
                {TextToken, " "},
                {RegisterToken, "R" + std::to_string(((insn & 0xf0) >> 0x4)) },
                {OperandSeparatorToken, ", "},
                {RegisterToken, "R" + std::to_string(((insn & 0xf00) >> 0x8)) }
            },
            {
                SHOper(OpType::REG, SHReg(R0 + ((insn & 0xf0) >> 0x4)), 0, false, false, false, 0, 4),
                SHOper(OpType::REG, SHReg(R0 + ((insn & 0xf00) >> 0x8)), 0, false, false, false, 0, 4)
            },
            false,
            2,
            addr
        );
    }

    if ((insn & 0xf00f) == 0x3007) {
        return SHInsn(
            SHOpCode::op_cmp_gt,
            {
                {InstructionToken, "cmp/gt"},
                {TextToken, " "},
                {RegisterToken, "R" + std::to_string(((insn & 0xf0) >> 0x4)) },
                {OperandSeparatorToken, ", "},
                {RegisterToken, "R" + std::to_string(((insn & 0xf00) >> 0x8)) }
            },
            {
                SHOper(OpType::REG, SHReg(R0 + ((insn & 0xf0) >> 0x4)), 0, false, false, false, 0, 4),
                SHOper(OpType::REG, SHReg(R0 + ((insn & 0xf00) >> 0x8)), 0, false, false, false, 0, 4)
            },
            false,
            2,
            addr
        );
    }

    if ((insn & 0xf0ff) == 0x4015) {
        return SHInsn(
            SHOpCode::op_cmp_pl,
            {
                {InstructionToken, "cmp/pl"},
                {TextToken, " "},
                {RegisterToken, "R" + std::to_string(((insn & 0xf00) >> 0x8)) }
            },
            {
                SHOper(OpType::REG, SHReg(R0 + ((insn & 0xf00) >> 0x8)), 0, false, false, false, 0, 4)
            },
            false,
            2,
            addr
        );
    }

    if ((insn & 0xf0ff) == 0x4011) {
        return SHInsn(
            SHOpCode::op_cmp_pz,
            {
                {InstructionToken, "cmp/pz"},
                {TextToken, " "},
                {RegisterToken, "R" + std::to_string(((insn & 0xf00) >> 0x8)) }
            },
            {
                SHOper(OpType::REG, SHReg(R0 + ((insn & 0xf00) >> 0x8)), 0, false, false, false, 0, 4)
            },
            false,
            2,
            addr
        );
    }

    if ((insn & 0xf00f) == 0x200c) {
        return SHInsn(
            SHOpCode::op_cmp_str,
            {
                {InstructionToken, "cmp/str"},
                {TextToken, " "},
                {RegisterToken, "R" + std::to_string(((insn & 0xf0) >> 0x4)) },
                {OperandSeparatorToken, ", "},
                {RegisterToken, "R" + std::to_string(((insn & 0xf00) >> 0x8)) }
            },
            {
                SHOper(OpType::REG, SHReg(R0 + ((insn & 0xf0) >> 0x4)), 0, false, false, false, 0, 4),
                SHOper(OpType::REG, SHReg(R0 + ((insn & 0xf00) >> 0x8)), 0, false, false, false, 0, 4)
            },
            false,
            2,
            addr
        );
    }

    if ((insn & 0xf0ff) == 0x4091) {
        return SHInsn(
            SHOpCode::op_clips_b,
            {
                {InstructionToken, "clips.b"},
                {TextToken, " "},
                {RegisterToken, "R" + std::to_string(((insn & 0xf00) >> 0x8)) }
            },
            {
                SHOper(OpType::REG, SHReg(R0 + ((insn & 0xf00) >> 0x8)), 0, false, false, false, 0, 4)
            },
            false,
            2,
            addr
        );
    }

    if ((insn & 0xf0ff) == 0x4095) {
        return SHInsn(
            SHOpCode::op_clips_w,
            {
                {InstructionToken, "clips.w"},
                {TextToken, " "},
                {RegisterToken, "R" + std::to_string(((insn & 0xf00) >> 0x8)) }
            },
            {
                SHOper(OpType::REG, SHReg(R0 + ((insn & 0xf00) >> 0x8)), 0, false, false, false, 0, 4)
            },
            false,
            2,
            addr
        );
    }

    if ((insn & 0xf0ff) == 0x4081) {
        return SHInsn(
            SHOpCode::op_clipu_b,
            {
                {InstructionToken, "clipu.b"},
                {TextToken, " "},
                {RegisterToken, "R" + std::to_string(((insn & 0xf00) >> 0x8)) }
            },
            {
                SHOper(OpType::REG, SHReg(R0 + ((insn & 0xf00) >> 0x8)), 0, false, false, false, 0, 4)
            },
            false,
            2,
            addr
        );
    }

    if ((insn & 0xf0ff) == 0x4085) {
        return SHInsn(
            SHOpCode::op_clipu_w,
            {
                {InstructionToken, "clipu.w"},
                {TextToken, " "},
                {RegisterToken, "R" + std::to_string(((insn & 0xf00) >> 0x8)) }
            },
            {
                SHOper(OpType::REG, SHReg(R0 + ((insn & 0xf00) >> 0x8)), 0, false, false, false, 0, 4)
            },
            false,
            2,
            addr
        );
    }

    if ((insn & 0xf00f) == 0x2007) {
        return SHInsn(
            SHOpCode::op_div0s,
            {
                {InstructionToken, "div0s"},
                {TextToken, " "},
                {RegisterToken, "R" + std::to_string(((insn & 0xf0) >> 0x4)) },
                {OperandSeparatorToken, ", "},
                {RegisterToken, "R" + std::to_string(((insn & 0xf00) >> 0x8)) }
            },
            {
                SHOper(OpType::REG, SHReg(R0 + ((insn & 0xf0) >> 0x4)), 0, false, false, false, 0, 4),
                SHOper(OpType::REG, SHReg(R0 + ((insn & 0xf00) >> 0x8)), 0, false, false, false, 0, 4)
            },
            false,
            2,
            addr
        );
    }

    if ((insn & 0xffff) == 0x0019) {
        return SHInsn(
            SHOpCode::op_div0u,
            {
                {InstructionToken, "div0u"},
                {TextToken, " "}
            },
            {
                
            },
            false,
            2,
            addr
        );
    }

    if ((insn & 0xf00f) == 0x3004) {
        return SHInsn(
            SHOpCode::op_div1,
            {
                {InstructionToken, "div1"},
                {TextToken, " "},
                {RegisterToken, "R" + std::to_string(((insn & 0xf0) >> 0x4)) },
                {OperandSeparatorToken, ", "},
                {RegisterToken, "R" + std::to_string(((insn & 0xf00) >> 0x8)) }
            },
            {
                SHOper(OpType::REG, SHReg(R0 + ((insn & 0xf0) >> 0x4)), 0, false, false, false, 0, 4),
                SHOper(OpType::REG, SHReg(R0 + ((insn & 0xf00) >> 0x8)), 0, false, false, false, 0, 4)
            },
            false,
            2,
            addr
        );
    }

    if ((insn & 0xf0ff) == 0x4094) {
        return SHInsn(
            SHOpCode::op_divs,
            {
                {InstructionToken, "divs"},
                {TextToken, " "},
                {RegisterToken, "R0"},
                {OperandSeparatorToken, ", "},
                {RegisterToken, "R" + std::to_string(((insn & 0xf00) >> 0x8)) }
            },
            {
                SHOper(OpType::REG, SHReg(R0), 0, false, false, false, 0, 4),
                SHOper(OpType::REG, SHReg(R0 + ((insn & 0xf00) >> 0x8)), 0, false, false, false, 0, 4)
            },
            false,
            2,
            addr
        );
    }

    if ((insn & 0xf0ff) == 0x4084) {
        return SHInsn(
            SHOpCode::op_divu,
            {
                {InstructionToken, "divu"},
                {TextToken, " "},
                {RegisterToken, "R0"},
                {OperandSeparatorToken, ", "},
                {RegisterToken, "R" + std::to_string(((insn & 0xf00) >> 0x8)) }
            },
            {
                SHOper(OpType::REG, SHReg(R0), 0, false, false, false, 0, 4),
                SHOper(OpType::REG, SHReg(R0 + ((insn & 0xf00) >> 0x8)), 0, false, false, false, 0, 4)
            },
            false,
            2,
            addr
        );
    }

    if ((insn & 0xf00f) == 0x300d) {
        return SHInsn(
            SHOpCode::op_dmuls_l,
            {
                {InstructionToken, "dmuls.l"},
                {TextToken, " "},
                {RegisterToken, "R" + std::to_string(((insn & 0xf0) >> 0x4)) },
                {OperandSeparatorToken, ", "},
                {RegisterToken, "R" + std::to_string(((insn & 0xf00) >> 0x8)) }
            },
            {
                SHOper(OpType::REG, SHReg(R0 + ((insn & 0xf0) >> 0x4)), 0, false, false, false, 0, 4),
                SHOper(OpType::REG, SHReg(R0 + ((insn & 0xf00) >> 0x8)), 0, false, false, false, 0, 4)
            },
            false,
            2,
            addr
        );
    }

    if ((insn & 0xf00f) == 0x3005) {
        return SHInsn(
            SHOpCode::op_dmulu_l,
            {
                {InstructionToken, "dmulu.l"},
                {TextToken, " "},
                {RegisterToken, "R" + std::to_string(((insn & 0xf0) >> 0x4)) },
                {OperandSeparatorToken, ", "},
                {RegisterToken, "R" + std::to_string(((insn & 0xf00) >> 0x8)) }
            },
            {
                SHOper(OpType::REG, SHReg(R0 + ((insn & 0xf0) >> 0x4)), 0, false, false, false, 0, 4),
                SHOper(OpType::REG, SHReg(R0 + ((insn & 0xf00) >> 0x8)), 0, false, false, false, 0, 4)
            },
            false,
            2,
            addr
        );
    }

    if ((insn & 0xf0ff) == 0x4010) {
        return SHInsn(
            SHOpCode::op_dt,
            {
                {InstructionToken, "dt"},
                {TextToken, " "},
                {RegisterToken, "R" + std::to_string(((insn & 0xf00) >> 0x8)) }
            },
            {
                SHOper(OpType::REG, SHReg(R0 + ((insn & 0xf00) >> 0x8)), 0, false, false, false, 0, 4)
            },
            false,
            2,
            addr
        );
    }

    if ((insn & 0xf00f) == 0x600e) {
        return SHInsn(
            SHOpCode::op_exts_b,
            {
                {InstructionToken, "exts.b"},
                {TextToken, " "},
                {RegisterToken, "R" + std::to_string(((insn & 0xf0) >> 0x4)) },
                {OperandSeparatorToken, ", "},
                {RegisterToken, "R" + std::to_string(((insn & 0xf00) >> 0x8)) }
            },
            {
                SHOper(OpType::REG, SHReg(R0 + ((insn & 0xf0) >> 0x4)), 0, false, false, false, 0, 4),
                SHOper(OpType::REG, SHReg(R0 + ((insn & 0xf00) >> 0x8)), 0, false, false, false, 0, 4)
            },
            false,
            2,
            addr
        );
    }

    if ((insn & 0xf00f) == 0x600f) {
        return SHInsn(
            SHOpCode::op_exts_w,
            {
                {InstructionToken, "exts.w"},
                {TextToken, " "},
                {RegisterToken, "R" + std::to_string(((insn & 0xf0) >> 0x4)) },
                {OperandSeparatorToken, ", "},
                {RegisterToken, "R" + std::to_string(((insn & 0xf00) >> 0x8)) }
            },
            {
                SHOper(OpType::REG, SHReg(R0 + ((insn & 0xf0) >> 0x4)), 0, false, false, false, 0, 4),
                SHOper(OpType::REG, SHReg(R0 + ((insn & 0xf00) >> 0x8)), 0, false, false, false, 0, 4)
            },
            false,
            2,
            addr
        );
    }

    if ((insn & 0xf00f) == 0x600c) {
        return SHInsn(
            SHOpCode::op_extu_b,
            {
                {InstructionToken, "extu.b"},
                {TextToken, " "},
                {RegisterToken, "R" + std::to_string(((insn & 0xf0) >> 0x4)) },
                {OperandSeparatorToken, ", "},
                {RegisterToken, "R" + std::to_string(((insn & 0xf00) >> 0x8)) }
            },
            {
                SHOper(OpType::REG, SHReg(R0 + ((insn & 0xf0) >> 0x4)), 0, false, false, false, 0, 4),
                SHOper(OpType::REG, SHReg(R0 + ((insn & 0xf00) >> 0x8)), 0, false, false, false, 0, 4)
            },
            false,
            2,
            addr
        );
    }

    if ((insn & 0xf00f) == 0x600d) {
        return SHInsn(
            SHOpCode::op_extu_w,
            {
                {InstructionToken, "extu.w"},
                {TextToken, " "},
                {RegisterToken, "R" + std::to_string(((insn & 0xf0) >> 0x4)) },
                {OperandSeparatorToken, ", "},
                {RegisterToken, "R" + std::to_string(((insn & 0xf00) >> 0x8)) }
            },
            {
                SHOper(OpType::REG, SHReg(R0 + ((insn & 0xf0) >> 0x4)), 0, false, false, false, 0, 4),
                SHOper(OpType::REG, SHReg(R0 + ((insn & 0xf00) >> 0x8)), 0, false, false, false, 0, 4)
            },
            false,
            2,
            addr
        );
    }

    if ((insn & 0xf00f) == 0x000f) {
        return SHInsn(
            SHOpCode::op_mac_l,
            {
                {InstructionToken, "mac.l"},
                {TextToken, " "},
                {TextToken, "@"},
                {RegisterToken, "R" + std::to_string(((insn & 0xf0) >> 0x4)) },
                {TextToken, "+"},
                {OperandSeparatorToken, ", "},
                {TextToken, "@"},
                {RegisterToken, "R" + std::to_string(((insn & 0xf00) >> 0x8)) },
                {TextToken, "+"}
            },
            {
                SHOper(OpType::REG, SHReg(R0 + ((insn & 0xf0) >> 0x4)), 0, true, false, false, 4, 4),
                SHOper(OpType::REG, SHReg(R0 + ((insn & 0xf00) >> 0x8)), 0, true, false, false, 4, 4)
            },
            false,
            2,
            addr
        );
    }

    if ((insn & 0xf00f) == 0x400f) {
        return SHInsn(
            SHOpCode::op_mac_w,
            {
                {InstructionToken, "mac.w"},
                {TextToken, " "},
                {TextToken, "@"},
                {RegisterToken, "R" + std::to_string(((insn & 0xf0) >> 0x4)) },
                {TextToken, "+"},
                {OperandSeparatorToken, ", "},
                {TextToken, "@"},
                {RegisterToken, "R" + std::to_string(((insn & 0xf00) >> 0x8)) },
                {TextToken, "+"}
            },
            {
                SHOper(OpType::REG, SHReg(R0 + ((insn & 0xf0) >> 0x4)), 0, true, false, false, 2, 4),
                SHOper(OpType::REG, SHReg(R0 + ((insn & 0xf00) >> 0x8)), 0, true, false, false, 2, 4)
            },
            false,
            2,
            addr
        );
    }

    if ((insn & 0xf00f) == 0x0007) {
        return SHInsn(
            SHOpCode::op_mul_l,
            {
                {InstructionToken, "mul.l"},
                {TextToken, " "},
                {RegisterToken, "R" + std::to_string(((insn & 0xf0) >> 0x4)) },
                {OperandSeparatorToken, ", "},
                {RegisterToken, "R" + std::to_string(((insn & 0xf00) >> 0x8)) }
            },
            {
                SHOper(OpType::REG, SHReg(R0 + ((insn & 0xf0) >> 0x4)), 0, false, false, false, 0, 4),
                SHOper(OpType::REG, SHReg(R0 + ((insn & 0xf00) >> 0x8)), 0, false, false, false, 0, 4)
            },
            false,
            2,
            addr
        );
    }

    if ((insn & 0xf0ff) == 0x4080) {
        return SHInsn(
            SHOpCode::op_mulr,
            {
                {InstructionToken, "mulr"},
                {TextToken, " "},
                {RegisterToken, "R0"},
                {OperandSeparatorToken, ", "},
                {RegisterToken, "R" + std::to_string(((insn & 0xf00) >> 0x8)) }
            },
            {
                SHOper(OpType::REG, SHReg(R0), 0, false, false, false, 0, 4),
                SHOper(OpType::REG, SHReg(R0 + ((insn & 0xf00) >> 0x8)), 0, false, false, false, 0, 4)
            },
            false,
            2,
            addr
        );
    }

    if ((insn & 0xf00f) == 0x200f) {
        return SHInsn(
            SHOpCode::op_muls_w,
            {
                {InstructionToken, "muls.w"},
                {TextToken, " "},
                {RegisterToken, "R" + std::to_string(((insn & 0xf0) >> 0x4)) },
                {OperandSeparatorToken, ", "},
                {RegisterToken, "R" + std::to_string(((insn & 0xf00) >> 0x8)) }
            },
            {
                SHOper(OpType::REG, SHReg(R0 + ((insn & 0xf0) >> 0x4)), 0, false, false, false, 0, 4),
                SHOper(OpType::REG, SHReg(R0 + ((insn & 0xf00) >> 0x8)), 0, false, false, false, 0, 4)
            },
            false,
            2,
            addr
        );
    }

    if ((insn & 0xf00f) == 0x200e) {
        return SHInsn(
            SHOpCode::op_mulu_w,
            {
                {InstructionToken, "mulu.w"},
                {TextToken, " "},
                {RegisterToken, "R" + std::to_string(((insn & 0xf0) >> 0x4)) },
                {OperandSeparatorToken, ", "},
                {RegisterToken, "R" + std::to_string(((insn & 0xf00) >> 0x8)) }
            },
            {
                SHOper(OpType::REG, SHReg(R0 + ((insn & 0xf0) >> 0x4)), 0, false, false, false, 0, 4),
                SHOper(OpType::REG, SHReg(R0 + ((insn & 0xf00) >> 0x8)), 0, false, false, false, 0, 4)
            },
            false,
            2,
            addr
        );
    }

    if ((insn & 0xf00f) == 0x600b) {
        return SHInsn(
            SHOpCode::op_neg,
            {
                {InstructionToken, "neg"},
                {TextToken, " "},
                {RegisterToken, "R" + std::to_string(((insn & 0xf0) >> 0x4)) },
                {OperandSeparatorToken, ", "},
                {RegisterToken, "R" + std::to_string(((insn & 0xf00) >> 0x8)) }
            },
            {
                SHOper(OpType::REG, SHReg(R0 + ((insn & 0xf0) >> 0x4)), 0, false, false, false, 0, 4),
                SHOper(OpType::REG, SHReg(R0 + ((insn & 0xf00) >> 0x8)), 0, false, false, false, 0, 4)
            },
            false,
            2,
            addr
        );
    }

    if ((insn & 0xf00f) == 0x600a) {
        return SHInsn(
            SHOpCode::op_negc,
            {
                {InstructionToken, "negc"},
                {TextToken, " "},
                {RegisterToken, "R" + std::to_string(((insn & 0xf0) >> 0x4)) },
                {OperandSeparatorToken, ", "},
                {RegisterToken, "R" + std::to_string(((insn & 0xf00) >> 0x8)) }
            },
            {
                SHOper(OpType::REG, SHReg(R0 + ((insn & 0xf0) >> 0x4)), 0, false, false, false, 0, 4),
                SHOper(OpType::REG, SHReg(R0 + ((insn & 0xf00) >> 0x8)), 0, false, false, false, 0, 4)
            },
            false,
            2,
            addr
        );
    }

    if ((insn & 0xf00f) == 0x3008) {
        return SHInsn(
            SHOpCode::op_sub,
            {
                {InstructionToken, "sub"},
                {TextToken, " "},
                {RegisterToken, "R" + std::to_string(((insn & 0xf0) >> 0x4)) },
                {OperandSeparatorToken, ", "},
                {RegisterToken, "R" + std::to_string(((insn & 0xf00) >> 0x8)) }
            },
            {
                SHOper(OpType::REG, SHReg(R0 + ((insn & 0xf0) >> 0x4)), 0, false, false, false, 0, 4),
                SHOper(OpType::REG, SHReg(R0 + ((insn & 0xf00) >> 0x8)), 0, false, false, false, 0, 4)
            },
            false,
            2,
            addr
        );
    }

    if ((insn & 0xf00f) == 0x300a) {
        return SHInsn(
            SHOpCode::op_subc,
            {
                {InstructionToken, "subc"},
                {TextToken, " "},
                {RegisterToken, "R" + std::to_string(((insn & 0xf0) >> 0x4)) },
                {OperandSeparatorToken, ", "},
                {RegisterToken, "R" + std::to_string(((insn & 0xf00) >> 0x8)) }
            },
            {
                SHOper(OpType::REG, SHReg(R0 + ((insn & 0xf0) >> 0x4)), 0, false, false, false, 0, 4),
                SHOper(OpType::REG, SHReg(R0 + ((insn & 0xf00) >> 0x8)), 0, false, false, false, 0, 4)
            },
            false,
            2,
            addr
        );
    }

    if ((insn & 0xf00f) == 0x300b) {
        return SHInsn(
            SHOpCode::op_subv,
            {
                {InstructionToken, "subv"},
                {TextToken, " "},
                {RegisterToken, "R" + std::to_string(((insn & 0xf0) >> 0x4)) },
                {OperandSeparatorToken, ", "},
                {RegisterToken, "R" + std::to_string(((insn & 0xf00) >> 0x8)) }
            },
            {
                SHOper(OpType::REG, SHReg(R0 + ((insn & 0xf0) >> 0x4)), 0, false, false, false, 0, 4),
                SHOper(OpType::REG, SHReg(R0 + ((insn & 0xf00) >> 0x8)), 0, false, false, false, 0, 4)
            },
            false,
            2,
            addr
        );
    }

    if ((insn & 0xf00f) == 0x2009) {
        return SHInsn(
            SHOpCode::op_and,
            {
                {InstructionToken, "and"},
                {TextToken, " "},
                {RegisterToken, "R" + std::to_string(((insn & 0xf0) >> 0x4)) },
                {OperandSeparatorToken, ", "},
                {RegisterToken, "R" + std::to_string(((insn & 0xf00) >> 0x8)) }
            },
            {
                SHOper(OpType::REG, SHReg(R0 + ((insn & 0xf0) >> 0x4)), 0, false, false, false, 0, 4),
                SHOper(OpType::REG, SHReg(R0 + ((insn & 0xf00) >> 0x8)), 0, false, false, false, 0, 4)
            },
            false,
            2,
            addr
        );
    }

    if ((insn & 0xff00) == 0xc900) {
        return SHInsn(
            SHOpCode::op_and,
            {
                {InstructionToken, "and"},
                {TextToken, " "},
                {PossibleAddressToken, int_to_hex((insn & 0xff))},
                {OperandSeparatorToken, ", "},
                {RegisterToken, "R0"}
            },
            {
                SHOper(OpType::IMM, SHReg::InvalidReg, (insn & 0xff), false, false, false, 0, 1),
                SHOper(OpType::REG, SHReg(R0), 0, false, false, false, 0, 4)
            },
            false,
            2,
            addr
        );
    }

    if ((insn & 0xff00) == 0xcd00) {
        return SHInsn(
            SHOpCode::op_and_b,
            {
                {InstructionToken, "and.b"},
                {TextToken, " "},
                {PossibleAddressToken, int_to_hex((insn & 0xff))},
                {OperandSeparatorToken, ", "},
                {TextToken, "@("},
                {RegisterToken, "R0"},
                {OperandSeparatorToken, ", "},
                {RegisterToken, "GBR"},
                {TextToken, ")"}
            },
            {
                SHOper(OpType::IMM, SHReg::InvalidReg, (insn & 0xff), false, false, false, 0, 1),
                SHOper(OpType::REG, SHReg(R0), 0, true, true, false, 0, 4),
                SHOper(OpType::REG, SHReg(GBR), 0, false, false, false, 0, 4)
            },
            false,
            2,
            addr
        );
    }

    if ((insn & 0xf00f) == 0x6007) {
        return SHInsn(
            SHOpCode::op_not,
            {
                {InstructionToken, "not"},
                {TextToken, " "},
                {RegisterToken, "R" + std::to_string(((insn & 0xf0) >> 0x4)) },
                {OperandSeparatorToken, ", "},
                {RegisterToken, "R" + std::to_string(((insn & 0xf00) >> 0x8)) }
            },
            {
                SHOper(OpType::REG, SHReg(R0 + ((insn & 0xf0) >> 0x4)), 0, false, false, false, 0, 4),
                SHOper(OpType::REG, SHReg(R0 + ((insn & 0xf00) >> 0x8)), 0, false, false, false, 0, 4)
            },
            false,
            2,
            addr
        );
    }

    if ((insn & 0xf00f) == 0x200b) {
        return SHInsn(
            SHOpCode::op_or,
            {
                {InstructionToken, "or"},
                {TextToken, " "},
                {RegisterToken, "R" + std::to_string(((insn & 0xf0) >> 0x4)) },
                {OperandSeparatorToken, ", "},
                {RegisterToken, "R" + std::to_string(((insn & 0xf00) >> 0x8)) }
            },
            {
                SHOper(OpType::REG, SHReg(R0 + ((insn & 0xf0) >> 0x4)), 0, false, false, false, 0, 4),
                SHOper(OpType::REG, SHReg(R0 + ((insn & 0xf00) >> 0x8)), 0, false, false, false, 0, 4)
            },
            false,
            2,
            addr
        );
    }

    if ((insn & 0xff00) == 0xcb00) {
        return SHInsn(
            SHOpCode::op_or,
            {
                {InstructionToken, "or"},
                {TextToken, " "},
                {PossibleAddressToken, int_to_hex((insn & 0xff))},
                {OperandSeparatorToken, ", "},
                {RegisterToken, "R0"}
            },
            {
                SHOper(OpType::IMM, SHReg::InvalidReg, (insn & 0xff), false, false, false, 0, 1),
                SHOper(OpType::REG, SHReg(R0), 0, false, false, false, 0, 4)
            },
            false,
            2,
            addr
        );
    }

    if ((insn & 0xff00) == 0xcf00) {
        return SHInsn(
            SHOpCode::op_or_b,
            {
                {InstructionToken, "or.b"},
                {TextToken, " "},
                {PossibleAddressToken, int_to_hex((insn & 0xff))},
                {OperandSeparatorToken, ", "},
                {TextToken, "@("},
                {RegisterToken, "R0"},
                {OperandSeparatorToken, ", "},
                {RegisterToken, "GBR"},
                {TextToken, ")"}
            },
            {
                SHOper(OpType::IMM, SHReg::InvalidReg, (insn & 0xff), false, false, false, 0, 1),
                SHOper(OpType::REG, SHReg(R0), 0, true, true, false, 0, 4),
                SHOper(OpType::REG, SHReg(GBR), 0, false, false, false, 0, 4)
            },
            false,
            2,
            addr
        );
    }

    if ((insn & 0xf0ff) == 0x401b) {
        return SHInsn(
            SHOpCode::op_tas_b,
            {
                {InstructionToken, "tas.b"},
                {TextToken, " "},
                {TextToken, "@"},
                {RegisterToken, "R" + std::to_string(((insn & 0xf00) >> 0x8)) }
            },
            {
                SHOper(OpType::REG, SHReg(R0 + ((insn & 0xf00) >> 0x8)), 0, true, false, false, 0, 4)
            },
            false,
            2,
            addr
        );
    }

    if ((insn & 0xf00f) == 0x2008) {
        return SHInsn(
            SHOpCode::op_tst,
            {
                {InstructionToken, "tst"},
                {TextToken, " "},
                {RegisterToken, "R" + std::to_string(((insn & 0xf0) >> 0x4)) },
                {OperandSeparatorToken, ", "},
                {RegisterToken, "R" + std::to_string(((insn & 0xf00) >> 0x8)) }
            },
            {
                SHOper(OpType::REG, SHReg(R0 + ((insn & 0xf0) >> 0x4)), 0, false, false, false, 0, 4),
                SHOper(OpType::REG, SHReg(R0 + ((insn & 0xf00) >> 0x8)), 0, false, false, false, 0, 4)
            },
            false,
            2,
            addr
        );
    }

    if ((insn & 0xff00) == 0xc800) {
        return SHInsn(
            SHOpCode::op_tst,
            {
                {InstructionToken, "tst"},
                {TextToken, " "},
                {PossibleAddressToken, int_to_hex((insn & 0xff))},
                {OperandSeparatorToken, ", "},
                {RegisterToken, "R0"}
            },
            {
                SHOper(OpType::IMM, SHReg::InvalidReg, (insn & 0xff), false, false, false, 0, 1),
                SHOper(OpType::REG, SHReg(R0), 0, false, false, false, 0, 4)
            },
            false,
            2,
            addr
        );
    }

    if ((insn & 0xff00) == 0xcc00) {
        return SHInsn(
            SHOpCode::op_tst_b,
            {
                {InstructionToken, "tst.b"},
                {TextToken, " "},
                {PossibleAddressToken, int_to_hex((insn & 0xff))},
                {OperandSeparatorToken, ", "},
                {TextToken, "@("},
                {RegisterToken, "R0"},
                {OperandSeparatorToken, ", "},
                {RegisterToken, "GBR"},
                {TextToken, ")"}
            },
            {
                SHOper(OpType::IMM, SHReg::InvalidReg, (insn & 0xff), false, false, false, 0, 1),
                SHOper(OpType::REG, SHReg(R0), 0, true, true, false, 0, 4),
                SHOper(OpType::REG, SHReg(GBR), 0, false, false, false, 0, 4)
            },
            false,
            2,
            addr
        );
    }

    if ((insn & 0xf00f) == 0x200a) {
        return SHInsn(
            SHOpCode::op_xor,
            {
                {InstructionToken, "xor"},
                {TextToken, " "},
                {RegisterToken, "R" + std::to_string(((insn & 0xf0) >> 0x4)) },
                {OperandSeparatorToken, ", "},
                {RegisterToken, "R" + std::to_string(((insn & 0xf00) >> 0x8)) }
            },
            {
                SHOper(OpType::REG, SHReg(R0 + ((insn & 0xf0) >> 0x4)), 0, false, false, false, 0, 4),
                SHOper(OpType::REG, SHReg(R0 + ((insn & 0xf00) >> 0x8)), 0, false, false, false, 0, 4)
            },
            false,
            2,
            addr
        );
    }

    if ((insn & 0xff00) == 0xca00) {
        return SHInsn(
            SHOpCode::op_xor,
            {
                {InstructionToken, "xor"},
                {TextToken, " "},
                {PossibleAddressToken, int_to_hex((insn & 0xff))},
                {OperandSeparatorToken, ", "},
                {RegisterToken, "R0"}
            },
            {
                SHOper(OpType::IMM, SHReg::InvalidReg, (insn & 0xff), false, false, false, 0, 1),
                SHOper(OpType::REG, SHReg(R0), 0, false, false, false, 0, 4)
            },
            false,
            2,
            addr
        );
    }

    if ((insn & 0xff00) == 0xce00) {
        return SHInsn(
            SHOpCode::op_xor_b,
            {
                {InstructionToken, "xor.b"},
                {TextToken, " "},
                {PossibleAddressToken, int_to_hex((insn & 0xff))},
                {OperandSeparatorToken, ", "},
                {TextToken, "@("},
                {RegisterToken, "R0"},
                {OperandSeparatorToken, ", "},
                {RegisterToken, "GBR"},
                {TextToken, ")"}
            },
            {
                SHOper(OpType::IMM, SHReg::InvalidReg, (insn & 0xff), false, false, false, 0, 1),
                SHOper(OpType::REG, SHReg(R0), 0, true, true, false, 0, 4),
                SHOper(OpType::REG, SHReg(GBR), 0, false, false, false, 0, 4)
            },
            false,
            2,
            addr
        );
    }

    if ((insn & 0xf0ff) == 0x4024) {
        return SHInsn(
            SHOpCode::op_rotcl,
            {
                {InstructionToken, "rotcl"},
                {TextToken, " "},
                {RegisterToken, "R" + std::to_string(((insn & 0xf00) >> 0x8)) }
            },
            {
                SHOper(OpType::REG, SHReg(R0 + ((insn & 0xf00) >> 0x8)), 0, false, false, false, 0, 4)
            },
            false,
            2,
            addr
        );
    }

    if ((insn & 0xf0ff) == 0x4025) {
        return SHInsn(
            SHOpCode::op_rotcr,
            {
                {InstructionToken, "rotcr"},
                {TextToken, " "},
                {RegisterToken, "R" + std::to_string(((insn & 0xf00) >> 0x8)) }
            },
            {
                SHOper(OpType::REG, SHReg(R0 + ((insn & 0xf00) >> 0x8)), 0, false, false, false, 0, 4)
            },
            false,
            2,
            addr
        );
    }

    if ((insn & 0xf0ff) == 0x4004) {
        return SHInsn(
            SHOpCode::op_rotl,
            {
                {InstructionToken, "rotl"},
                {TextToken, " "},
                {RegisterToken, "R" + std::to_string(((insn & 0xf00) >> 0x8)) }
            },
            {
                SHOper(OpType::REG, SHReg(R0 + ((insn & 0xf00) >> 0x8)), 0, false, false, false, 0, 4)
            },
            false,
            2,
            addr
        );
    }

    if ((insn & 0xf0ff) == 0x4005) {
        return SHInsn(
            SHOpCode::op_rotr,
            {
                {InstructionToken, "rotr"},
                {TextToken, " "},
                {RegisterToken, "R" + std::to_string(((insn & 0xf00) >> 0x8)) }
            },
            {
                SHOper(OpType::REG, SHReg(R0 + ((insn & 0xf00) >> 0x8)), 0, false, false, false, 0, 4)
            },
            false,
            2,
            addr
        );
    }

    if ((insn & 0xf00f) == 0x400c) {
        return SHInsn(
            SHOpCode::op_shad,
            {
                {InstructionToken, "shad"},
                {TextToken, " "},
                {RegisterToken, "R" + std::to_string(((insn & 0xf0) >> 0x4)) },
                {OperandSeparatorToken, ", "},
                {RegisterToken, "R" + std::to_string(((insn & 0xf00) >> 0x8)) }
            },
            {
                SHOper(OpType::REG, SHReg(R0 + ((insn & 0xf0) >> 0x4)), 0, false, false, false, 0, 4),
                SHOper(OpType::REG, SHReg(R0 + ((insn & 0xf00) >> 0x8)), 0, false, false, false, 0, 4)
            },
            false,
            2,
            addr
        );
    }

    if ((insn & 0xf0ff) == 0x4020) {
        return SHInsn(
            SHOpCode::op_shal,
            {
                {InstructionToken, "shal"},
                {TextToken, " "},
                {RegisterToken, "R" + std::to_string(((insn & 0xf00) >> 0x8)) }
            },
            {
                SHOper(OpType::REG, SHReg(R0 + ((insn & 0xf00) >> 0x8)), 0, false, false, false, 0, 4)
            },
            false,
            2,
            addr
        );
    }

    if ((insn & 0xf0ff) == 0x4021) {
        return SHInsn(
            SHOpCode::op_shar,
            {
                {InstructionToken, "shar"},
                {TextToken, " "},
                {RegisterToken, "R" + std::to_string(((insn & 0xf00) >> 0x8)) }
            },
            {
                SHOper(OpType::REG, SHReg(R0 + ((insn & 0xf00) >> 0x8)), 0, false, false, false, 0, 4)
            },
            false,
            2,
            addr
        );
    }

    if ((insn & 0xf00f) == 0x400d) {
        return SHInsn(
            SHOpCode::op_shld,
            {
                {InstructionToken, "shld"},
                {TextToken, " "},
                {RegisterToken, "R" + std::to_string(((insn & 0xf0) >> 0x4)) },
                {OperandSeparatorToken, ", "},
                {RegisterToken, "R" + std::to_string(((insn & 0xf00) >> 0x8)) }
            },
            {
                SHOper(OpType::REG, SHReg(R0 + ((insn & 0xf0) >> 0x4)), 0, false, false, false, 0, 4),
                SHOper(OpType::REG, SHReg(R0 + ((insn & 0xf00) >> 0x8)), 0, false, false, false, 0, 4)
            },
            false,
            2,
            addr
        );
    }

    if ((insn & 0xf0ff) == 0x4000) {
        return SHInsn(
            SHOpCode::op_shll,
            {
                {InstructionToken, "shll"},
                {TextToken, " "},
                {RegisterToken, "R" + std::to_string(((insn & 0xf00) >> 0x8)) }
            },
            {
                SHOper(OpType::REG, SHReg(R0 + ((insn & 0xf00) >> 0x8)), 0, false, false, false, 0, 4)
            },
            false,
            2,
            addr
        );
    }

    if ((insn & 0xf0ff) == 0x4008) {
        return SHInsn(
            SHOpCode::op_shll2,
            {
                {InstructionToken, "shll2"},
                {TextToken, " "},
                {RegisterToken, "R" + std::to_string(((insn & 0xf00) >> 0x8)) }
            },
            {
                SHOper(OpType::REG, SHReg(R0 + ((insn & 0xf00) >> 0x8)), 0, false, false, false, 0, 4)
            },
            false,
            2,
            addr
        );
    }

    if ((insn & 0xf0ff) == 0x4018) {
        return SHInsn(
            SHOpCode::op_shll8,
            {
                {InstructionToken, "shll8"},
                {TextToken, " "},
                {RegisterToken, "R" + std::to_string(((insn & 0xf00) >> 0x8)) }
            },
            {
                SHOper(OpType::REG, SHReg(R0 + ((insn & 0xf00) >> 0x8)), 0, false, false, false, 0, 4)
            },
            false,
            2,
            addr
        );
    }

    if ((insn & 0xf0ff) == 0x4028) {
        return SHInsn(
            SHOpCode::op_shll16,
            {
                {InstructionToken, "shll16"},
                {TextToken, " "},
                {RegisterToken, "R" + std::to_string(((insn & 0xf00) >> 0x8)) }
            },
            {
                SHOper(OpType::REG, SHReg(R0 + ((insn & 0xf00) >> 0x8)), 0, false, false, false, 0, 4)
            },
            false,
            2,
            addr
        );
    }

    if ((insn & 0xf0ff) == 0x4001) {
        return SHInsn(
            SHOpCode::op_shlr,
            {
                {InstructionToken, "shlr"},
                {TextToken, " "},
                {RegisterToken, "R" + std::to_string(((insn & 0xf00) >> 0x8)) }
            },
            {
                SHOper(OpType::REG, SHReg(R0 + ((insn & 0xf00) >> 0x8)), 0, false, false, false, 0, 4)
            },
            false,
            2,
            addr
        );
    }

    if ((insn & 0xf0ff) == 0x4009) {
        return SHInsn(
            SHOpCode::op_shlr2,
            {
                {InstructionToken, "shlr2"},
                {TextToken, " "},
                {RegisterToken, "R" + std::to_string(((insn & 0xf00) >> 0x8)) }
            },
            {
                SHOper(OpType::REG, SHReg(R0 + ((insn & 0xf00) >> 0x8)), 0, false, false, false, 0, 4)
            },
            false,
            2,
            addr
        );
    }

    if ((insn & 0xf0ff) == 0x4019) {
        return SHInsn(
            SHOpCode::op_shlr8,
            {
                {InstructionToken, "shlr8"},
                {TextToken, " "},
                {RegisterToken, "R" + std::to_string(((insn & 0xf00) >> 0x8)) }
            },
            {
                SHOper(OpType::REG, SHReg(R0 + ((insn & 0xf00) >> 0x8)), 0, false, false, false, 0, 4)
            },
            false,
            2,
            addr
        );
    }

    if ((insn & 0xf0ff) == 0x4029) {
        return SHInsn(
            SHOpCode::op_shlr16,
            {
                {InstructionToken, "shlr16"},
                {TextToken, " "},
                {RegisterToken, "R" + std::to_string(((insn & 0xf00) >> 0x8)) }
            },
            {
                SHOper(OpType::REG, SHReg(R0 + ((insn & 0xf00) >> 0x8)), 0, false, false, false, 0, 4)
            },
            false,
            2,
            addr
        );
    }

    if ((insn & 0xff00) == 0x8b00) {
        return SHInsn(
            SHOpCode::op_bf,
            {
                {InstructionToken, "bf"},
                {TextToken, " "},
                {PossibleAddressToken, int_to_hex((label_disp(insn & 0xff, addr, 128, 255)))}
            },
            {
                SHOper(OpType::DISP, SHReg::InvalidReg, (label_disp(insn & 0xff, addr, 128, 255)), false, false, true, 0, 2)
            },
            false,
            2,
            addr
        );
    }

    if ((insn & 0xff00) == 0x8f00) {
        return SHInsn(
            SHOpCode::op_bf_s,
            {
                {InstructionToken, "bf/s"},
                {TextToken, " "},
                {PossibleAddressToken, int_to_hex((label_disp(insn & 0xff, addr, 128, 255)))}
            },
            {
                SHOper(OpType::DISP, SHReg::InvalidReg, (label_disp(insn & 0xff, addr, 128, 255)), false, false, true, 0, 2)
            },
            true,
            2,
            addr
        );
    }

    if ((insn & 0xff00) == 0x8900) {
        return SHInsn(
            SHOpCode::op_bt,
            {
                {InstructionToken, "bt"},
                {TextToken, " "},
                {PossibleAddressToken, int_to_hex((label_disp(insn & 0xff, addr, 128, 255)))}
            },
            {
                SHOper(OpType::DISP, SHReg::InvalidReg, (label_disp(insn & 0xff, addr, 128, 255)), false, false, true, 0, 2)
            },
            false,
            2,
            addr
        );
    }

    if ((insn & 0xff00) == 0x8d00) {
        return SHInsn(
            SHOpCode::op_bt_s,
            {
                {InstructionToken, "bt/s"},
                {TextToken, " "},
                {PossibleAddressToken, int_to_hex((label_disp(insn & 0xff, addr, 128, 255)))}
            },
            {
                SHOper(OpType::DISP, SHReg::InvalidReg, (label_disp(insn & 0xff, addr, 128, 255)), false, false, true, 0, 2)
            },
            true,
            2,
            addr
        );
    }

    if ((insn & 0xf000) == 0xa000) {
        return SHInsn(
            SHOpCode::op_bra,
            {
                {InstructionToken, "bra"},
                {TextToken, " "},
                {PossibleAddressToken, int_to_hex((label_disp(insn & 0xfff, addr, 2048, 4095)))}
            },
            {
                SHOper(OpType::DISP, SHReg::InvalidReg, (label_disp(insn & 0xfff, addr, 2048, 4095)), false, false, true, 0, 2)
            },
            true,
            2,
            addr
        );
    }

    if ((insn & 0xf0ff) == 0x0023) {
        return SHInsn(
            SHOpCode::op_braf,
            {
                {InstructionToken, "braf"},
                {TextToken, " "},
                {RegisterToken, "R" + std::to_string(((insn & 0xf00) >> 0x8)) }
            },
            {
                SHOper(OpType::REG, SHReg(R0 + ((insn & 0xf00) >> 0x8)), 0, false, false, false, 0, 4)
            },
            true,
            2,
            addr
        );
    }

    if ((insn & 0xf000) == 0xb000) {
        return SHInsn(
            SHOpCode::op_bsr,
            {
                {InstructionToken, "bsr"},
                {TextToken, " "},
                {PossibleAddressToken, int_to_hex((label_disp(insn & 0xfff, addr, 2048, 4095)))}
            },
            {
                SHOper(OpType::DISP, SHReg::InvalidReg, (label_disp(insn & 0xfff, addr, 2048, 4095)), false, false, true, 0, 2)
            },
            true,
            2,
            addr
        );
    }

    if ((insn & 0xf0ff) == 0x0003) {
        return SHInsn(
            SHOpCode::op_bsrf,
            {
                {InstructionToken, "bsrf"},
                {TextToken, " "},
                {RegisterToken, "R" + std::to_string(((insn & 0xf00) >> 0x8)) }
            },
            {
                SHOper(OpType::REG, SHReg(R0 + ((insn & 0xf00) >> 0x8)), 0, false, false, false, 0, 4)
            },
            true,
            2,
            addr
        );
    }

    if ((insn & 0xf0ff) == 0x402b) {
        return SHInsn(
            SHOpCode::op_jmp,
            {
                {InstructionToken, "jmp"},
                {TextToken, " "},
                {TextToken, "@"},
                {RegisterToken, "R" + std::to_string(((insn & 0xf00) >> 0x8)) }
            },
            {
                SHOper(OpType::REG, SHReg(R0 + ((insn & 0xf00) >> 0x8)), 0, true, false, false, 0, 4)
            },
            true,
            2,
            addr
        );
    }

    if ((insn & 0xf0ff) == 0x400b) {
        return SHInsn(
            SHOpCode::op_jsr,
            {
                {InstructionToken, "jsr"},
                {TextToken, " "},
                {TextToken, "@"},
                {RegisterToken, "R" + std::to_string(((insn & 0xf00) >> 0x8)) }
            },
            {
                SHOper(OpType::REG, SHReg(R0 + ((insn & 0xf00) >> 0x8)), 0, true, false, false, 0, 4)
            },
            true,
            2,
            addr
        );
    }

    if ((insn & 0xf0ff) == 0x404b) {
        return SHInsn(
            SHOpCode::op_jsr_n,
            {
                {InstructionToken, "jsr/n"},
                {TextToken, " "},
                {TextToken, "@"},
                {RegisterToken, "R" + std::to_string(((insn & 0xf00) >> 0x8)) }
            },
            {
                SHOper(OpType::REG, SHReg(R0 + ((insn & 0xf00) >> 0x8)), 0, true, false, false, 0, 4)
            },
            false,
            2,
            addr
        );
    }

    if ((insn & 0xff00) == 0x8300) {
        return SHInsn(
            SHOpCode::op_jsr_n,
            {
                {InstructionToken, "jsr/n"},
                {TextToken, " "},
                {TextToken, "@@("},
                {PossibleAddressToken, int_to_hex((insn & 0xff))},
                {OperandSeparatorToken, ", "},
                {RegisterToken, "TBR"},
                {TextToken, ")"}
            },
            {
                SHOper(OpType::DISP, SHReg::InvalidReg, (insn & 0xff), true, true, false, 0, 1),
                SHOper(OpType::REG, SHReg(TBR), 0, false, false, false, 0, 4)
            },
            false,
            2,
            addr
        );
    }

    if ((insn & 0xffff) == 0x000b) {
        return SHInsn(
            SHOpCode::op_rts,
            {
                {InstructionToken, "rts"},
                {TextToken, " "}
            },
            {
                
            },
            true,
            2,
            addr
        );
    }

    if ((insn & 0xffff) == 0x006b) {
        return SHInsn(
            SHOpCode::op_rts_n,
            {
                {InstructionToken, "rts/n"},
                {TextToken, " "}
            },
            {
                
            },
            false,
            2,
            addr
        );
    }

    if ((insn & 0xf0ff) == 0x007b) {
        return SHInsn(
            SHOpCode::op_rtv_n,
            {
                {InstructionToken, "rtv/n"},
                {TextToken, " "},
                {RegisterToken, "R" + std::to_string(((insn & 0xf00) >> 0x8)) }
            },
            {
                SHOper(OpType::REG, SHReg(R0 + ((insn & 0xf00) >> 0x8)), 0, false, false, false, 0, 4)
            },
            false,
            2,
            addr
        );
    }

    if ((insn & 0xffff) == 0x0028) {
        return SHInsn(
            SHOpCode::op_clrmac,
            {
                {InstructionToken, "clrmac"},
                {TextToken, " "}
            },
            {
                
            },
            false,
            2,
            addr
        );
    }

    if ((insn & 0xffff) == 0x0048) {
        return SHInsn(
            SHOpCode::op_clrs,
            {
                {InstructionToken, "clrs"},
                {TextToken, " "}
            },
            {
                
            },
            false,
            2,
            addr
        );
    }

    if ((insn & 0xffff) == 0x0008) {
        return SHInsn(
            SHOpCode::op_clrt,
            {
                {InstructionToken, "clrt"},
                {TextToken, " "}
            },
            {
                
            },
            false,
            2,
            addr
        );
    }

    if ((insn & 0xf0ff) == 0x00e3) {
        return SHInsn(
            SHOpCode::op_icbi,
            {
                {InstructionToken, "icbi"},
                {TextToken, " "},
                {TextToken, "@"},
                {RegisterToken, "R" + std::to_string(((insn & 0xf00) >> 0x8)) }
            },
            {
                SHOper(OpType::REG, SHReg(R0 + ((insn & 0xf00) >> 0x8)), 0, true, false, false, 0, 4)
            },
            false,
            2,
            addr
        );
    }

    if ((insn & 0xf0ff) == 0x40e5) {
        return SHInsn(
            SHOpCode::op_ldbank,
            {
                {InstructionToken, "ldbank"},
                {TextToken, " "},
                {TextToken, "@"},
                {RegisterToken, "R" + std::to_string(((insn & 0xf00) >> 0x8)) },
                {OperandSeparatorToken, ", "},
                {RegisterToken, "R0"}
            },
            {
                SHOper(OpType::REG, SHReg(R0 + ((insn & 0xf00) >> 0x8)), 0, true, false, false, 0, 4),
                SHOper(OpType::REG, SHReg(R0), 0, false, false, false, 0, 4)
            },
            false,
            2,
            addr
        );
    }

    if ((insn & 0xf0ff) == 0x400e) {
        return SHInsn(
            SHOpCode::op_ldc,
            {
                {InstructionToken, "ldc"},
                {TextToken, " "},
                {RegisterToken, "R" + std::to_string(((insn & 0xf00) >> 0x8)) },
                {OperandSeparatorToken, ", "},
                {RegisterToken, "SR"}
            },
            {
                SHOper(OpType::REG, SHReg(R0 + ((insn & 0xf00) >> 0x8)), 0, false, false, false, 0, 4),
                SHOper(OpType::REG, SHReg(SR), 0, false, false, false, 0, 4)
            },
            false,
            2,
            addr
        );
    }

    if ((insn & 0xf0ff) == 0x4007) {
        return SHInsn(
            SHOpCode::op_ldc_l,
            {
                {InstructionToken, "ldc.l"},
                {TextToken, " "},
                {TextToken, "@"},
                {RegisterToken, "R" + std::to_string(((insn & 0xf00) >> 0x8)) },
                {TextToken, "+"},
                {OperandSeparatorToken, ", "},
                {RegisterToken, "SR"}
            },
            {
                SHOper(OpType::REG, SHReg(R0 + ((insn & 0xf00) >> 0x8)), 0, true, false, false, 4, 4),
                SHOper(OpType::REG, SHReg(SR), 0, false, false, false, 0, 4)
            },
            false,
            2,
            addr
        );
    }

    if ((insn & 0xf0ff) == 0x404a) {
        return SHInsn(
            SHOpCode::op_ldc,
            {
                {InstructionToken, "ldc"},
                {TextToken, " "},
                {RegisterToken, "R" + std::to_string(((insn & 0xf00) >> 0x8)) },
                {OperandSeparatorToken, ", "},
                {RegisterToken, "TBR"}
            },
            {
                SHOper(OpType::REG, SHReg(R0 + ((insn & 0xf00) >> 0x8)), 0, false, false, false, 0, 4),
                SHOper(OpType::REG, SHReg(TBR), 0, false, false, false, 0, 4)
            },
            false,
            2,
            addr
        );
    }

    if ((insn & 0xf0ff) == 0x401e) {
        return SHInsn(
            SHOpCode::op_ldc,
            {
                {InstructionToken, "ldc"},
                {TextToken, " "},
                {RegisterToken, "R" + std::to_string(((insn & 0xf00) >> 0x8)) },
                {OperandSeparatorToken, ", "},
                {RegisterToken, "GBR"}
            },
            {
                SHOper(OpType::REG, SHReg(R0 + ((insn & 0xf00) >> 0x8)), 0, false, false, false, 0, 4),
                SHOper(OpType::REG, SHReg(GBR), 0, false, false, false, 0, 4)
            },
            false,
            2,
            addr
        );
    }

    if ((insn & 0xf0ff) == 0x4017) {
        return SHInsn(
            SHOpCode::op_ldc_l,
            {
                {InstructionToken, "ldc.l"},
                {TextToken, " "},
                {TextToken, "@"},
                {RegisterToken, "R" + std::to_string(((insn & 0xf00) >> 0x8)) },
                {TextToken, "+"},
                {OperandSeparatorToken, ", "},
                {RegisterToken, "GBR"}
            },
            {
                SHOper(OpType::REG, SHReg(R0 + ((insn & 0xf00) >> 0x8)), 0, true, false, false, 4, 4),
                SHOper(OpType::REG, SHReg(GBR), 0, false, false, false, 0, 4)
            },
            false,
            2,
            addr
        );
    }

    if ((insn & 0xf0ff) == 0x402e) {
        return SHInsn(
            SHOpCode::op_ldc,
            {
                {InstructionToken, "ldc"},
                {TextToken, " "},
                {RegisterToken, "R" + std::to_string(((insn & 0xf00) >> 0x8)) },
                {OperandSeparatorToken, ", "},
                {RegisterToken, "VBR"}
            },
            {
                SHOper(OpType::REG, SHReg(R0 + ((insn & 0xf00) >> 0x8)), 0, false, false, false, 0, 4),
                SHOper(OpType::REG, SHReg(VBR), 0, false, false, false, 0, 4)
            },
            false,
            2,
            addr
        );
    }

    if ((insn & 0xf0ff) == 0x4027) {
        return SHInsn(
            SHOpCode::op_ldc_l,
            {
                {InstructionToken, "ldc.l"},
                {TextToken, " "},
                {TextToken, "@"},
                {RegisterToken, "R" + std::to_string(((insn & 0xf00) >> 0x8)) },
                {TextToken, "+"},
                {OperandSeparatorToken, ", "},
                {RegisterToken, "VBR"}
            },
            {
                SHOper(OpType::REG, SHReg(R0 + ((insn & 0xf00) >> 0x8)), 0, true, false, false, 4, 4),
                SHOper(OpType::REG, SHReg(VBR), 0, false, false, false, 0, 4)
            },
            false,
            2,
            addr
        );
    }

    if ((insn & 0xf0ff) == 0x405e) {
        return SHInsn(
            SHOpCode::op_ldc,
            {
                {InstructionToken, "ldc"},
                {TextToken, " "},
                {RegisterToken, "R" + std::to_string(((insn & 0xf00) >> 0x8)) },
                {OperandSeparatorToken, ", "},
                {RegisterToken, "MOD"}
            },
            {
                SHOper(OpType::REG, SHReg(R0 + ((insn & 0xf00) >> 0x8)), 0, false, false, false, 0, 4),
                SHOper(OpType::REG, SHReg(MOD), 0, false, false, false, 0, 4)
            },
            false,
            2,
            addr
        );
    }

    if ((insn & 0xf0ff) == 0x4057) {
        return SHInsn(
            SHOpCode::op_ldc_l,
            {
                {InstructionToken, "ldc.l"},
                {TextToken, " "},
                {TextToken, "@"},
                {RegisterToken, "R" + std::to_string(((insn & 0xf00) >> 0x8)) },
                {TextToken, "+"},
                {OperandSeparatorToken, ", "},
                {RegisterToken, "MOD"}
            },
            {
                SHOper(OpType::REG, SHReg(R0 + ((insn & 0xf00) >> 0x8)), 0, true, false, false, 4, 4),
                SHOper(OpType::REG, SHReg(MOD), 0, false, false, false, 0, 4)
            },
            false,
            2,
            addr
        );
    }

    if ((insn & 0xf0ff) == 0x407e) {
        return SHInsn(
            SHOpCode::op_ldc,
            {
                {InstructionToken, "ldc"},
                {TextToken, " "},
                {RegisterToken, "R" + std::to_string(((insn & 0xf00) >> 0x8)) },
                {OperandSeparatorToken, ", "},
                {RegisterToken, "RE"}
            },
            {
                SHOper(OpType::REG, SHReg(R0 + ((insn & 0xf00) >> 0x8)), 0, false, false, false, 0, 4),
                SHOper(OpType::REG, SHReg(RE), 0, false, false, false, 0, 4)
            },
            false,
            2,
            addr
        );
    }

    if ((insn & 0xf0ff) == 0x4077) {
        return SHInsn(
            SHOpCode::op_ldc_l,
            {
                {InstructionToken, "ldc.l"},
                {TextToken, " "},
                {TextToken, "@"},
                {RegisterToken, "R" + std::to_string(((insn & 0xf00) >> 0x8)) },
                {TextToken, "+"},
                {OperandSeparatorToken, ", "},
                {RegisterToken, "RE"}
            },
            {
                SHOper(OpType::REG, SHReg(R0 + ((insn & 0xf00) >> 0x8)), 0, true, false, false, 4, 4),
                SHOper(OpType::REG, SHReg(RE), 0, false, false, false, 0, 4)
            },
            false,
            2,
            addr
        );
    }

    if ((insn & 0xf0ff) == 0x406e) {
        return SHInsn(
            SHOpCode::op_ldc,
            {
                {InstructionToken, "ldc"},
                {TextToken, " "},
                {RegisterToken, "R" + std::to_string(((insn & 0xf00) >> 0x8)) },
                {OperandSeparatorToken, ", "},
                {RegisterToken, "RS"}
            },
            {
                SHOper(OpType::REG, SHReg(R0 + ((insn & 0xf00) >> 0x8)), 0, false, false, false, 0, 4),
                SHOper(OpType::REG, SHReg(RS), 0, false, false, false, 0, 4)
            },
            false,
            2,
            addr
        );
    }

    if ((insn & 0xf0ff) == 0x4067) {
        return SHInsn(
            SHOpCode::op_ldc_l,
            {
                {InstructionToken, "ldc.l"},
                {TextToken, " "},
                {TextToken, "@"},
                {RegisterToken, "R" + std::to_string(((insn & 0xf00) >> 0x8)) },
                {TextToken, "+"},
                {OperandSeparatorToken, ", "},
                {RegisterToken, "RS"}
            },
            {
                SHOper(OpType::REG, SHReg(R0 + ((insn & 0xf00) >> 0x8)), 0, true, false, false, 4, 4),
                SHOper(OpType::REG, SHReg(RS), 0, false, false, false, 0, 4)
            },
            false,
            2,
            addr
        );
    }

    if ((insn & 0xf0ff) == 0x403a) {
        return SHInsn(
            SHOpCode::op_ldc,
            {
                {InstructionToken, "ldc"},
                {TextToken, " "},
                {RegisterToken, "R" + std::to_string(((insn & 0xf00) >> 0x8)) },
                {OperandSeparatorToken, ", "},
                {RegisterToken, "SGR"}
            },
            {
                SHOper(OpType::REG, SHReg(R0 + ((insn & 0xf00) >> 0x8)), 0, false, false, false, 0, 4),
                SHOper(OpType::REG, SHReg(SGR), 0, false, false, false, 0, 4)
            },
            false,
            2,
            addr
        );
    }

    if ((insn & 0xf0ff) == 0x4036) {
        return SHInsn(
            SHOpCode::op_ldc_l,
            {
                {InstructionToken, "ldc.l"},
                {TextToken, " "},
                {TextToken, "@"},
                {RegisterToken, "R" + std::to_string(((insn & 0xf00) >> 0x8)) },
                {TextToken, "+"},
                {OperandSeparatorToken, ", "},
                {RegisterToken, "SGR"}
            },
            {
                SHOper(OpType::REG, SHReg(R0 + ((insn & 0xf00) >> 0x8)), 0, true, false, false, 4, 4),
                SHOper(OpType::REG, SHReg(SGR), 0, false, false, false, 0, 4)
            },
            false,
            2,
            addr
        );
    }

    if ((insn & 0xf0ff) == 0x403e) {
        return SHInsn(
            SHOpCode::op_ldc,
            {
                {InstructionToken, "ldc"},
                {TextToken, " "},
                {RegisterToken, "R" + std::to_string(((insn & 0xf00) >> 0x8)) },
                {OperandSeparatorToken, ", "},
                {RegisterToken, "SSR"}
            },
            {
                SHOper(OpType::REG, SHReg(R0 + ((insn & 0xf00) >> 0x8)), 0, false, false, false, 0, 4),
                SHOper(OpType::REG, SHReg(SSR), 0, false, false, false, 0, 4)
            },
            false,
            2,
            addr
        );
    }

    if ((insn & 0xf0ff) == 0x4037) {
        return SHInsn(
            SHOpCode::op_ldc_l,
            {
                {InstructionToken, "ldc.l"},
                {TextToken, " "},
                {TextToken, "@"},
                {RegisterToken, "R" + std::to_string(((insn & 0xf00) >> 0x8)) },
                {TextToken, "+"},
                {OperandSeparatorToken, ", "},
                {RegisterToken, "SSR"}
            },
            {
                SHOper(OpType::REG, SHReg(R0 + ((insn & 0xf00) >> 0x8)), 0, true, false, false, 4, 4),
                SHOper(OpType::REG, SHReg(SSR), 0, false, false, false, 0, 4)
            },
            false,
            2,
            addr
        );
    }

    if ((insn & 0xf0ff) == 0x404e) {
        return SHInsn(
            SHOpCode::op_ldc,
            {
                {InstructionToken, "ldc"},
                {TextToken, " "},
                {RegisterToken, "R" + std::to_string(((insn & 0xf00) >> 0x8)) },
                {OperandSeparatorToken, ", "},
                {RegisterToken, "SPC"}
            },
            {
                SHOper(OpType::REG, SHReg(R0 + ((insn & 0xf00) >> 0x8)), 0, false, false, false, 0, 4),
                SHOper(OpType::REG, SHReg(SPC), 0, false, false, false, 0, 4)
            },
            false,
            2,
            addr
        );
    }

    if ((insn & 0xf0ff) == 0x4047) {
        return SHInsn(
            SHOpCode::op_ldc_l,
            {
                {InstructionToken, "ldc.l"},
                {TextToken, " "},
                {TextToken, "@"},
                {RegisterToken, "R" + std::to_string(((insn & 0xf00) >> 0x8)) },
                {TextToken, "+"},
                {OperandSeparatorToken, ", "},
                {RegisterToken, "SPC"}
            },
            {
                SHOper(OpType::REG, SHReg(R0 + ((insn & 0xf00) >> 0x8)), 0, true, false, false, 4, 4),
                SHOper(OpType::REG, SHReg(SPC), 0, false, false, false, 0, 4)
            },
            false,
            2,
            addr
        );
    }

    if ((insn & 0xf0ff) == 0x40fa) {
        return SHInsn(
            SHOpCode::op_ldc,
            {
                {InstructionToken, "ldc"},
                {TextToken, " "},
                {RegisterToken, "R" + std::to_string(((insn & 0xf00) >> 0x8)) },
                {OperandSeparatorToken, ", "},
                {RegisterToken, "DBR"}
            },
            {
                SHOper(OpType::REG, SHReg(R0 + ((insn & 0xf00) >> 0x8)), 0, false, false, false, 0, 4),
                SHOper(OpType::REG, SHReg(DBR), 0, false, false, false, 0, 4)
            },
            false,
            2,
            addr
        );
    }

    if ((insn & 0xf0ff) == 0x40f6) {
        return SHInsn(
            SHOpCode::op_ldc_l,
            {
                {InstructionToken, "ldc.l"},
                {TextToken, " "},
                {TextToken, "@"},
                {RegisterToken, "R" + std::to_string(((insn & 0xf00) >> 0x8)) },
                {TextToken, "+"},
                {OperandSeparatorToken, ", "},
                {RegisterToken, "DBR"}
            },
            {
                SHOper(OpType::REG, SHReg(R0 + ((insn & 0xf00) >> 0x8)), 0, true, false, false, 4, 4),
                SHOper(OpType::REG, SHReg(DBR), 0, false, false, false, 0, 4)
            },
            false,
            2,
            addr
        );
    }

    if ((insn & 0xf0ff) == 0x408e) {
        return SHInsn(
            SHOpCode::op_ldc,
            {
                {InstructionToken, "ldc"},
                {TextToken, " "},
                {RegisterToken, "R" + std::to_string(((insn & 0xf00) >> 0x8)) },
                {OperandSeparatorToken, ", "},
                {RegisterToken, "R" + std::to_string(((insn & 0x70) >> 0x4)) + "_BANK" }
            },
            {
                SHOper(OpType::REG, SHReg(R0 + ((insn & 0xf00) >> 0x8)), 0, false, false, false, 0, 4),
                SHOper(OpType::REG, SHReg(R0_BANK + ((insn & 0x70) >> 0x4)), 0, false, false, false, 0, 4)
            },
            false,
            2,
            addr
        );
    }

    if ((insn & 0xf0ff) == 0x4087) {
        return SHInsn(
            SHOpCode::op_ldc_l,
            {
                {InstructionToken, "ldc.l"},
                {TextToken, " "},
                {TextToken, "@"},
                {RegisterToken, "R" + std::to_string(((insn & 0xf00) >> 0x8)) },
                {TextToken, "+"},
                {OperandSeparatorToken, ", "},
                {RegisterToken, "R" + std::to_string(((insn & 0x70) >> 0x4)) + "_BANK" }
            },
            {
                SHOper(OpType::REG, SHReg(R0 + ((insn & 0xf00) >> 0x8)), 0, true, false, false, 4, 4),
                SHOper(OpType::REG, SHReg(R0_BANK + ((insn & 0x70) >> 0x4)), 0, false, false, false, 0, 4)
            },
            false,
            2,
            addr
        );
    }

    if ((insn & 0xff00) == 0x8e00) {
        return SHInsn(
            SHOpCode::op_ldre,
            {
                {InstructionToken, "ldre"},
                {TextToken, " "},
                {TextToken, "@("},
                {PossibleAddressToken, int_to_hex((insn & 0xff))},
                {OperandSeparatorToken, ", "},
                {RegisterToken, "PC"},
                {TextToken, ")"}
            },
            {
                SHOper(OpType::DISP, SHReg::InvalidReg, (insn & 0xff), true, true, false, 0, 1),
                SHOper(OpType::REG, SHReg(PC), 0, false, false, false, 0, 4)
            },
            false,
            2,
            addr
        );
    }

    if ((insn & 0xff00) == 0x8c00) {
        return SHInsn(
            SHOpCode::op_ldrs,
            {
                {InstructionToken, "ldrs"},
                {TextToken, " "},
                {TextToken, "@("},
                {PossibleAddressToken, int_to_hex((insn & 0xff))},
                {OperandSeparatorToken, ", "},
                {RegisterToken, "PC"},
                {TextToken, ")"}
            },
            {
                SHOper(OpType::DISP, SHReg::InvalidReg, (insn & 0xff), true, true, false, 0, 1),
                SHOper(OpType::REG, SHReg(PC), 0, false, false, false, 0, 4)
            },
            false,
            2,
            addr
        );
    }

    if ((insn & 0xf0ff) == 0x400a) {
        return SHInsn(
            SHOpCode::op_lds,
            {
                {InstructionToken, "lds"},
                {TextToken, " "},
                {RegisterToken, "R" + std::to_string(((insn & 0xf00) >> 0x8)) },
                {OperandSeparatorToken, ", "},
                {RegisterToken, "MACH"}
            },
            {
                SHOper(OpType::REG, SHReg(R0 + ((insn & 0xf00) >> 0x8)), 0, false, false, false, 0, 4),
                SHOper(OpType::REG, SHReg(MACH), 0, false, false, false, 0, 4)
            },
            false,
            2,
            addr
        );
    }

    if ((insn & 0xf0ff) == 0x4006) {
        return SHInsn(
            SHOpCode::op_lds_l,
            {
                {InstructionToken, "lds.l"},
                {TextToken, " "},
                {TextToken, "@"},
                {RegisterToken, "R" + std::to_string(((insn & 0xf00) >> 0x8)) },
                {TextToken, "+"},
                {OperandSeparatorToken, ", "},
                {RegisterToken, "MACH"}
            },
            {
                SHOper(OpType::REG, SHReg(R0 + ((insn & 0xf00) >> 0x8)), 0, true, false, false, 4, 4),
                SHOper(OpType::REG, SHReg(MACH), 0, false, false, false, 0, 4)
            },
            false,
            2,
            addr
        );
    }

    if ((insn & 0xf0ff) == 0x401a) {
        return SHInsn(
            SHOpCode::op_lds,
            {
                {InstructionToken, "lds"},
                {TextToken, " "},
                {RegisterToken, "R" + std::to_string(((insn & 0xf00) >> 0x8)) },
                {OperandSeparatorToken, ", "},
                {RegisterToken, "MACL"}
            },
            {
                SHOper(OpType::REG, SHReg(R0 + ((insn & 0xf00) >> 0x8)), 0, false, false, false, 0, 4),
                SHOper(OpType::REG, SHReg(MACL), 0, false, false, false, 0, 4)
            },
            false,
            2,
            addr
        );
    }

    if ((insn & 0xf0ff) == 0x4016) {
        return SHInsn(
            SHOpCode::op_lds_l,
            {
                {InstructionToken, "lds.l"},
                {TextToken, " "},
                {TextToken, "@"},
                {RegisterToken, "R" + std::to_string(((insn & 0xf00) >> 0x8)) },
                {TextToken, "+"},
                {OperandSeparatorToken, ", "},
                {RegisterToken, "MACL"}
            },
            {
                SHOper(OpType::REG, SHReg(R0 + ((insn & 0xf00) >> 0x8)), 0, true, false, false, 4, 4),
                SHOper(OpType::REG, SHReg(MACL), 0, false, false, false, 0, 4)
            },
            false,
            2,
            addr
        );
    }

    if ((insn & 0xf0ff) == 0x402a) {
        return SHInsn(
            SHOpCode::op_lds,
            {
                {InstructionToken, "lds"},
                {TextToken, " "},
                {RegisterToken, "R" + std::to_string(((insn & 0xf00) >> 0x8)) },
                {OperandSeparatorToken, ", "},
                {RegisterToken, "PR"}
            },
            {
                SHOper(OpType::REG, SHReg(R0 + ((insn & 0xf00) >> 0x8)), 0, false, false, false, 0, 4),
                SHOper(OpType::REG, SHReg(PR), 0, false, false, false, 0, 4)
            },
            false,
            2,
            addr
        );
    }

    if ((insn & 0xf0ff) == 0x4026) {
        return SHInsn(
            SHOpCode::op_lds_l,
            {
                {InstructionToken, "lds.l"},
                {TextToken, " "},
                {TextToken, "@"},
                {RegisterToken, "R" + std::to_string(((insn & 0xf00) >> 0x8)) },
                {TextToken, "+"},
                {OperandSeparatorToken, ", "},
                {RegisterToken, "PR"}
            },
            {
                SHOper(OpType::REG, SHReg(R0 + ((insn & 0xf00) >> 0x8)), 0, true, false, false, 4, 4),
                SHOper(OpType::REG, SHReg(PR), 0, false, false, false, 0, 4)
            },
            false,
            2,
            addr
        );
    }

    if ((insn & 0xf0ff) == 0x406a) {
        return SHInsn(
            SHOpCode::op_lds,
            {
                {InstructionToken, "lds"},
                {TextToken, " "},
                {RegisterToken, "R" + std::to_string(((insn & 0xf00) >> 0x8)) },
                {OperandSeparatorToken, ", "},
                {RegisterToken, "DSR"}
            },
            {
                SHOper(OpType::REG, SHReg(R0 + ((insn & 0xf00) >> 0x8)), 0, false, false, false, 0, 4),
                SHOper(OpType::REG, SHReg(DSR), 0, false, false, false, 0, 4)
            },
            false,
            2,
            addr
        );
    }

    if ((insn & 0xf0ff) == 0x4066) {
        return SHInsn(
            SHOpCode::op_lds_l,
            {
                {InstructionToken, "lds.l"},
                {TextToken, " "},
                {TextToken, "@"},
                {RegisterToken, "R" + std::to_string(((insn & 0xf00) >> 0x8)) },
                {TextToken, "+"},
                {OperandSeparatorToken, ", "},
                {RegisterToken, "DSR"}
            },
            {
                SHOper(OpType::REG, SHReg(R0 + ((insn & 0xf00) >> 0x8)), 0, true, false, false, 4, 4),
                SHOper(OpType::REG, SHReg(DSR), 0, false, false, false, 0, 4)
            },
            false,
            2,
            addr
        );
    }

    if ((insn & 0xf0ff) == 0x4076) {
        return SHInsn(
            SHOpCode::op_lds,
            {
                {InstructionToken, "lds"},
                {TextToken, " "},
                {RegisterToken, "R" + std::to_string(((insn & 0xf00) >> 0x8)) },
                {OperandSeparatorToken, ", "},
                {RegisterToken, "A0"}
            },
            {
                SHOper(OpType::REG, SHReg(R0 + ((insn & 0xf00) >> 0x8)), 0, false, false, false, 0, 4),
                SHOper(OpType::REG, SHReg(A0), 0, false, false, false, 0, 4)
            },
            false,
            2,
            addr
        );
    }

    if ((insn & 0xf0ff) == 0x4076) {
        return SHInsn(
            SHOpCode::op_lds_l,
            {
                {InstructionToken, "lds.l"},
                {TextToken, " "},
                {TextToken, "@"},
                {RegisterToken, "R" + std::to_string(((insn & 0xf00) >> 0x8)) },
                {TextToken, "+"},
                {OperandSeparatorToken, ", "},
                {RegisterToken, "A0"}
            },
            {
                SHOper(OpType::REG, SHReg(R0 + ((insn & 0xf00) >> 0x8)), 0, true, false, false, 4, 4),
                SHOper(OpType::REG, SHReg(A0), 0, false, false, false, 0, 4)
            },
            false,
            2,
            addr
        );
    }

    if ((insn & 0xf0ff) == 0x408a) {
        return SHInsn(
            SHOpCode::op_lds,
            {
                {InstructionToken, "lds"},
                {TextToken, " "},
                {RegisterToken, "R" + std::to_string(((insn & 0xf00) >> 0x8)) },
                {OperandSeparatorToken, ", "},
                {RegisterToken, "X0"}
            },
            {
                SHOper(OpType::REG, SHReg(R0 + ((insn & 0xf00) >> 0x8)), 0, false, false, false, 0, 4),
                SHOper(OpType::REG, SHReg(X0), 0, false, false, false, 0, 4)
            },
            false,
            2,
            addr
        );
    }

    if ((insn & 0xf0ff) == 0x4086) {
        return SHInsn(
            SHOpCode::op_lds_l,
            {
                {InstructionToken, "lds.l"},
                {TextToken, " "},
                {TextToken, "@"},
                {RegisterToken, "R" + std::to_string(((insn & 0xf00) >> 0x8)) },
                {TextToken, "+"},
                {OperandSeparatorToken, ", "},
                {RegisterToken, "X0"}
            },
            {
                SHOper(OpType::REG, SHReg(R0 + ((insn & 0xf00) >> 0x8)), 0, true, false, false, 4, 4),
                SHOper(OpType::REG, SHReg(X0), 0, false, false, false, 0, 4)
            },
            false,
            2,
            addr
        );
    }

    if ((insn & 0xf0ff) == 0x409a) {
        return SHInsn(
            SHOpCode::op_lds,
            {
                {InstructionToken, "lds"},
                {TextToken, " "},
                {RegisterToken, "R" + std::to_string(((insn & 0xf00) >> 0x8)) },
                {OperandSeparatorToken, ", "},
                {RegisterToken, "X1"}
            },
            {
                SHOper(OpType::REG, SHReg(R0 + ((insn & 0xf00) >> 0x8)), 0, false, false, false, 0, 4),
                SHOper(OpType::REG, SHReg(X1), 0, false, false, false, 0, 4)
            },
            false,
            2,
            addr
        );
    }

    if ((insn & 0xf0ff) == 0x4096) {
        return SHInsn(
            SHOpCode::op_lds_l,
            {
                {InstructionToken, "lds.l"},
                {TextToken, " "},
                {TextToken, "@"},
                {RegisterToken, "R" + std::to_string(((insn & 0xf00) >> 0x8)) },
                {TextToken, "+"},
                {OperandSeparatorToken, ", "},
                {RegisterToken, "X1"}
            },
            {
                SHOper(OpType::REG, SHReg(R0 + ((insn & 0xf00) >> 0x8)), 0, true, false, false, 4, 4),
                SHOper(OpType::REG, SHReg(X1), 0, false, false, false, 0, 4)
            },
            false,
            2,
            addr
        );
    }

    if ((insn & 0xf0ff) == 0x40aa) {
        return SHInsn(
            SHOpCode::op_lds,
            {
                {InstructionToken, "lds"},
                {TextToken, " "},
                {RegisterToken, "R" + std::to_string(((insn & 0xf00) >> 0x8)) },
                {OperandSeparatorToken, ", "},
                {RegisterToken, "Y0"}
            },
            {
                SHOper(OpType::REG, SHReg(R0 + ((insn & 0xf00) >> 0x8)), 0, false, false, false, 0, 4),
                SHOper(OpType::REG, SHReg(Y0), 0, false, false, false, 0, 4)
            },
            false,
            2,
            addr
        );
    }

    if ((insn & 0xf0ff) == 0x40a6) {
        return SHInsn(
            SHOpCode::op_lds_l,
            {
                {InstructionToken, "lds.l"},
                {TextToken, " "},
                {TextToken, "@"},
                {RegisterToken, "R" + std::to_string(((insn & 0xf00) >> 0x8)) },
                {TextToken, "+"},
                {OperandSeparatorToken, ", "},
                {RegisterToken, "Y0"}
            },
            {
                SHOper(OpType::REG, SHReg(R0 + ((insn & 0xf00) >> 0x8)), 0, true, false, false, 4, 4),
                SHOper(OpType::REG, SHReg(Y0), 0, false, false, false, 0, 4)
            },
            false,
            2,
            addr
        );
    }

    if ((insn & 0xf0ff) == 0x40ba) {
        return SHInsn(
            SHOpCode::op_lds,
            {
                {InstructionToken, "lds"},
                {TextToken, " "},
                {RegisterToken, "R" + std::to_string(((insn & 0xf00) >> 0x8)) },
                {OperandSeparatorToken, ", "},
                {RegisterToken, "Y1"}
            },
            {
                SHOper(OpType::REG, SHReg(R0 + ((insn & 0xf00) >> 0x8)), 0, false, false, false, 0, 4),
                SHOper(OpType::REG, SHReg(Y1), 0, false, false, false, 0, 4)
            },
            false,
            2,
            addr
        );
    }

    if ((insn & 0xf0ff) == 0x40b6) {
        return SHInsn(
            SHOpCode::op_lds_l,
            {
                {InstructionToken, "lds.l"},
                {TextToken, " "},
                {TextToken, "@"},
                {RegisterToken, "R" + std::to_string(((insn & 0xf00) >> 0x8)) },
                {TextToken, "+"},
                {OperandSeparatorToken, ", "},
                {RegisterToken, "Y1"}
            },
            {
                SHOper(OpType::REG, SHReg(R0 + ((insn & 0xf00) >> 0x8)), 0, true, false, false, 4, 4),
                SHOper(OpType::REG, SHReg(Y1), 0, false, false, false, 0, 4)
            },
            false,
            2,
            addr
        );
    }

    if ((insn & 0xffff) == 0x0038) {
        return SHInsn(
            SHOpCode::op_ldtlb,
            {
                {InstructionToken, "ldtlb"},
                {TextToken, " "}
            },
            {
                
            },
            false,
            2,
            addr
        );
    }

    if ((insn & 0xf0ff) == 0x00c3) {
        return SHInsn(
            SHOpCode::op_movca_l,
            {
                {InstructionToken, "movca.l"},
                {TextToken, " "},
                {RegisterToken, "R0"},
                {OperandSeparatorToken, ", "},
                {TextToken, "@"},
                {RegisterToken, "R" + std::to_string(((insn & 0xf00) >> 0x8)) }
            },
            {
                SHOper(OpType::REG, SHReg(R0), 0, false, false, false, 0, 4),
                SHOper(OpType::REG, SHReg(R0 + ((insn & 0xf00) >> 0x8)), 0, true, false, false, 0, 4)
            },
            false,
            2,
            addr
        );
    }

    if ((insn & 0xffff) == 0x0009) {
        return SHInsn(
            SHOpCode::op_nop,
            {
                {InstructionToken, "nop"},
                {TextToken, " "}
            },
            {
                
            },
            false,
            2,
            addr
        );
    }

    if ((insn & 0xf0ff) == 0x0093) {
        return SHInsn(
            SHOpCode::op_ocbi,
            {
                {InstructionToken, "ocbi"},
                {TextToken, " "},
                {TextToken, "@"},
                {RegisterToken, "R" + std::to_string(((insn & 0xf00) >> 0x8)) }
            },
            {
                SHOper(OpType::REG, SHReg(R0 + ((insn & 0xf00) >> 0x8)), 0, true, false, false, 0, 4)
            },
            false,
            2,
            addr
        );
    }

    if ((insn & 0xf0ff) == 0x00a3) {
        return SHInsn(
            SHOpCode::op_ocbp,
            {
                {InstructionToken, "ocbp"},
                {TextToken, " "},
                {TextToken, "@"},
                {RegisterToken, "R" + std::to_string(((insn & 0xf00) >> 0x8)) }
            },
            {
                SHOper(OpType::REG, SHReg(R0 + ((insn & 0xf00) >> 0x8)), 0, true, false, false, 0, 4)
            },
            false,
            2,
            addr
        );
    }

    if ((insn & 0xf0ff) == 0x00b3) {
        return SHInsn(
            SHOpCode::op_ocbwb,
            {
                {InstructionToken, "ocbwb"},
                {TextToken, " "},
                {TextToken, "@"},
                {RegisterToken, "R" + std::to_string(((insn & 0xf00) >> 0x8)) }
            },
            {
                SHOper(OpType::REG, SHReg(R0 + ((insn & 0xf00) >> 0x8)), 0, true, false, false, 0, 4)
            },
            false,
            2,
            addr
        );
    }

    if ((insn & 0xf0ff) == 0x0083) {
        return SHInsn(
            SHOpCode::op_pref,
            {
                {InstructionToken, "pref"},
                {TextToken, " "},
                {TextToken, "@"},
                {RegisterToken, "R" + std::to_string(((insn & 0xf00) >> 0x8)) }
            },
            {
                SHOper(OpType::REG, SHReg(R0 + ((insn & 0xf00) >> 0x8)), 0, true, false, false, 0, 4)
            },
            false,
            2,
            addr
        );
    }

    if ((insn & 0xf0ff) == 0x00d3) {
        return SHInsn(
            SHOpCode::op_prefi,
            {
                {InstructionToken, "prefi"},
                {TextToken, " "},
                {TextToken, "@"},
                {RegisterToken, "R" + std::to_string(((insn & 0xf00) >> 0x8)) }
            },
            {
                SHOper(OpType::REG, SHReg(R0 + ((insn & 0xf00) >> 0x8)), 0, true, false, false, 0, 4)
            },
            false,
            2,
            addr
        );
    }

    if ((insn & 0xffff) == 0x005b) {
        return SHInsn(
            SHOpCode::op_resbank,
            {
                {InstructionToken, "resbank"},
                {TextToken, " "}
            },
            {
                
            },
            false,
            2,
            addr
        );
    }

    if ((insn & 0xffff) == 0x002b) {
        return SHInsn(
            SHOpCode::op_rte,
            {
                {InstructionToken, "rte"},
                {TextToken, " "}
            },
            {
                
            },
            true,
            2,
            addr
        );
    }

    if ((insn & 0xf0ff) == 0x4014) {
        return SHInsn(
            SHOpCode::op_setrc,
            {
                {InstructionToken, "setrc"},
                {TextToken, " "},
                {RegisterToken, "R" + std::to_string(((insn & 0x0) >> 0x0)) }
            },
            {
                SHOper(OpType::REG, SHReg(R0 + ((insn & 0x0) >> 0x0)), 0, false, false, false, 0, 4)
            },
            false,
            2,
            addr
        );
    }

    if ((insn & 0xff00) == 0x8200) {
        return SHInsn(
            SHOpCode::op_setrc,
            {
                {InstructionToken, "setrc"},
                {TextToken, " "},
                {PossibleAddressToken, int_to_hex((insn & 0xff))}
            },
            {
                SHOper(OpType::IMM, SHReg::InvalidReg, (insn & 0xff), false, false, false, 0, 1)
            },
            false,
            2,
            addr
        );
    }

    if ((insn & 0xffff) == 0x0058) {
        return SHInsn(
            SHOpCode::op_sets,
            {
                {InstructionToken, "sets"},
                {TextToken, " "}
            },
            {
                
            },
            false,
            2,
            addr
        );
    }

    if ((insn & 0xffff) == 0x0018) {
        return SHInsn(
            SHOpCode::op_sett,
            {
                {InstructionToken, "sett"},
                {TextToken, " "}
            },
            {
                
            },
            false,
            2,
            addr
        );
    }

    if ((insn & 0xffff) == 0x001b) {
        return SHInsn(
            SHOpCode::op_sleep,
            {
                {InstructionToken, "sleep"},
                {TextToken, " "}
            },
            {
                
            },
            false,
            2,
            addr
        );
    }

    if ((insn & 0xf0ff) == 0x40e1) {
        return SHInsn(
            SHOpCode::op_stbank,
            {
                {InstructionToken, "stbank"},
                {TextToken, " "},
                {RegisterToken, "R0"},
                {OperandSeparatorToken, ", "},
                {TextToken, "@"},
                {RegisterToken, "R" + std::to_string(((insn & 0xf00) >> 0x8)) }
            },
            {
                SHOper(OpType::REG, SHReg(R0), 0, false, false, false, 0, 4),
                SHOper(OpType::REG, SHReg(R0 + ((insn & 0xf00) >> 0x8)), 0, true, false, false, 0, 4)
            },
            false,
            2,
            addr
        );
    }

    if ((insn & 0xf0ff) == 0x0002) {
        return SHInsn(
            SHOpCode::op_stc,
            {
                {InstructionToken, "stc"},
                {TextToken, " "},
                {RegisterToken, "SR"},
                {OperandSeparatorToken, ", "},
                {RegisterToken, "R" + std::to_string(((insn & 0xf00) >> 0x8)) }
            },
            {
                SHOper(OpType::REG, SHReg(SR), 0, false, false, false, 0, 4),
                SHOper(OpType::REG, SHReg(R0 + ((insn & 0xf00) >> 0x8)), 0, false, false, false, 0, 4)
            },
            false,
            2,
            addr
        );
    }

    if ((insn & 0xf0ff) == 0x4003) {
        return SHInsn(
            SHOpCode::op_stc_l,
            {
                {InstructionToken, "stc.l"},
                {TextToken, " "},
                {RegisterToken, "SR"},
                {OperandSeparatorToken, ", "},
                {TextToken, "@-"},
                {RegisterToken, "R" + std::to_string(((insn & 0xf00) >> 0x8)) }
            },
            {
                SHOper(OpType::REG, SHReg(SR), 0, false, false, false, 0, 4),
                SHOper(OpType::REG, SHReg(R0 + ((insn & 0xf00) >> 0x8)), 0, true, false, false, -4, 4)
            },
            false,
            2,
            addr
        );
    }

    if ((insn & 0xf0ff) == 0x004a) {
        return SHInsn(
            SHOpCode::op_stc,
            {
                {InstructionToken, "stc"},
                {TextToken, " "},
                {RegisterToken, "TBR"},
                {OperandSeparatorToken, ", "},
                {RegisterToken, "R" + std::to_string(((insn & 0xf00) >> 0x8)) }
            },
            {
                SHOper(OpType::REG, SHReg(TBR), 0, false, false, false, 0, 4),
                SHOper(OpType::REG, SHReg(R0 + ((insn & 0xf00) >> 0x8)), 0, false, false, false, 0, 4)
            },
            false,
            2,
            addr
        );
    }

    if ((insn & 0xf0ff) == 0x0012) {
        return SHInsn(
            SHOpCode::op_stc,
            {
                {InstructionToken, "stc"},
                {TextToken, " "},
                {RegisterToken, "GBR"},
                {OperandSeparatorToken, ", "},
                {RegisterToken, "R" + std::to_string(((insn & 0xf00) >> 0x8)) }
            },
            {
                SHOper(OpType::REG, SHReg(GBR), 0, false, false, false, 0, 4),
                SHOper(OpType::REG, SHReg(R0 + ((insn & 0xf00) >> 0x8)), 0, false, false, false, 0, 4)
            },
            false,
            2,
            addr
        );
    }

    if ((insn & 0xf0ff) == 0x4013) {
        return SHInsn(
            SHOpCode::op_stc_l,
            {
                {InstructionToken, "stc.l"},
                {TextToken, " "},
                {RegisterToken, "GBR"},
                {OperandSeparatorToken, ", "},
                {TextToken, "@-"},
                {RegisterToken, "R" + std::to_string(((insn & 0xf00) >> 0x8)) }
            },
            {
                SHOper(OpType::REG, SHReg(GBR), 0, false, false, false, 0, 4),
                SHOper(OpType::REG, SHReg(R0 + ((insn & 0xf00) >> 0x8)), 0, true, false, false, -4, 4)
            },
            false,
            2,
            addr
        );
    }

    if ((insn & 0xf0ff) == 0x0022) {
        return SHInsn(
            SHOpCode::op_stc,
            {
                {InstructionToken, "stc"},
                {TextToken, " "},
                {RegisterToken, "VBR"},
                {OperandSeparatorToken, ", "},
                {RegisterToken, "R" + std::to_string(((insn & 0xf00) >> 0x8)) }
            },
            {
                SHOper(OpType::REG, SHReg(VBR), 0, false, false, false, 0, 4),
                SHOper(OpType::REG, SHReg(R0 + ((insn & 0xf00) >> 0x8)), 0, false, false, false, 0, 4)
            },
            false,
            2,
            addr
        );
    }

    if ((insn & 0xf0ff) == 0x4023) {
        return SHInsn(
            SHOpCode::op_stc_l,
            {
                {InstructionToken, "stc.l"},
                {TextToken, " "},
                {RegisterToken, "VBR"},
                {OperandSeparatorToken, ", "},
                {TextToken, "@-"},
                {RegisterToken, "R" + std::to_string(((insn & 0xf00) >> 0x8)) }
            },
            {
                SHOper(OpType::REG, SHReg(VBR), 0, false, false, false, 0, 4),
                SHOper(OpType::REG, SHReg(R0 + ((insn & 0xf00) >> 0x8)), 0, true, false, false, -4, 4)
            },
            false,
            2,
            addr
        );
    }

    if ((insn & 0xf0ff) == 0x0052) {
        return SHInsn(
            SHOpCode::op_stc,
            {
                {InstructionToken, "stc"},
                {TextToken, " "},
                {RegisterToken, "MOD"},
                {OperandSeparatorToken, ", "},
                {RegisterToken, "R" + std::to_string(((insn & 0xf00) >> 0x8)) }
            },
            {
                SHOper(OpType::REG, SHReg(MOD), 0, false, false, false, 0, 4),
                SHOper(OpType::REG, SHReg(R0 + ((insn & 0xf00) >> 0x8)), 0, false, false, false, 0, 4)
            },
            false,
            2,
            addr
        );
    }

    if ((insn & 0xf0ff) == 0x4053) {
        return SHInsn(
            SHOpCode::op_stc_l,
            {
                {InstructionToken, "stc.l"},
                {TextToken, " "},
                {RegisterToken, "MOD"},
                {OperandSeparatorToken, ", "},
                {TextToken, "@-"},
                {RegisterToken, "R" + std::to_string(((insn & 0xf00) >> 0x8)) }
            },
            {
                SHOper(OpType::REG, SHReg(MOD), 0, false, false, false, 0, 4),
                SHOper(OpType::REG, SHReg(R0 + ((insn & 0xf00) >> 0x8)), 0, true, false, false, -4, 4)
            },
            false,
            2,
            addr
        );
    }

    if ((insn & 0xf0ff) == 0x0072) {
        return SHInsn(
            SHOpCode::op_stc,
            {
                {InstructionToken, "stc"},
                {TextToken, " "},
                {RegisterToken, "RE"},
                {OperandSeparatorToken, ", "},
                {RegisterToken, "R" + std::to_string(((insn & 0xf00) >> 0x8)) }
            },
            {
                SHOper(OpType::REG, SHReg(RE), 0, false, false, false, 0, 4),
                SHOper(OpType::REG, SHReg(R0 + ((insn & 0xf00) >> 0x8)), 0, false, false, false, 0, 4)
            },
            false,
            2,
            addr
        );
    }

    if ((insn & 0xf0ff) == 0x4073) {
        return SHInsn(
            SHOpCode::op_stc_l,
            {
                {InstructionToken, "stc.l"},
                {TextToken, " "},
                {RegisterToken, "RE"},
                {OperandSeparatorToken, ", "},
                {TextToken, "@-"},
                {RegisterToken, "R" + std::to_string(((insn & 0xf00) >> 0x8)) }
            },
            {
                SHOper(OpType::REG, SHReg(RE), 0, false, false, false, 0, 4),
                SHOper(OpType::REG, SHReg(R0 + ((insn & 0xf00) >> 0x8)), 0, true, false, false, -4, 4)
            },
            false,
            2,
            addr
        );
    }

    if ((insn & 0xf0ff) == 0x0062) {
        return SHInsn(
            SHOpCode::op_stc,
            {
                {InstructionToken, "stc"},
                {TextToken, " "},
                {RegisterToken, "RS"},
                {OperandSeparatorToken, ", "},
                {RegisterToken, "R" + std::to_string(((insn & 0xf00) >> 0x8)) }
            },
            {
                SHOper(OpType::REG, SHReg(RS), 0, false, false, false, 0, 4),
                SHOper(OpType::REG, SHReg(R0 + ((insn & 0xf00) >> 0x8)), 0, false, false, false, 0, 4)
            },
            false,
            2,
            addr
        );
    }

    if ((insn & 0xf0ff) == 0x4063) {
        return SHInsn(
            SHOpCode::op_stc_l,
            {
                {InstructionToken, "stc.l"},
                {TextToken, " "},
                {RegisterToken, "RS"},
                {OperandSeparatorToken, ", "},
                {TextToken, "@-"},
                {RegisterToken, "R" + std::to_string(((insn & 0xf00) >> 0x8)) }
            },
            {
                SHOper(OpType::REG, SHReg(RS), 0, false, false, false, 0, 4),
                SHOper(OpType::REG, SHReg(R0 + ((insn & 0xf00) >> 0x8)), 0, true, false, false, -4, 4)
            },
            false,
            2,
            addr
        );
    }

    if ((insn & 0xf0ff) == 0x003a) {
        return SHInsn(
            SHOpCode::op_stc,
            {
                {InstructionToken, "stc"},
                {TextToken, " "},
                {RegisterToken, "SGR"},
                {OperandSeparatorToken, ", "},
                {RegisterToken, "R" + std::to_string(((insn & 0xf00) >> 0x8)) }
            },
            {
                SHOper(OpType::REG, SHReg(SGR), 0, false, false, false, 0, 4),
                SHOper(OpType::REG, SHReg(R0 + ((insn & 0xf00) >> 0x8)), 0, false, false, false, 0, 4)
            },
            false,
            2,
            addr
        );
    }

    if ((insn & 0xf0ff) == 0x4032) {
        return SHInsn(
            SHOpCode::op_stc_l,
            {
                {InstructionToken, "stc.l"},
                {TextToken, " "},
                {RegisterToken, "SGR"},
                {OperandSeparatorToken, ", "},
                {TextToken, "@-"},
                {RegisterToken, "R" + std::to_string(((insn & 0xf00) >> 0x8)) }
            },
            {
                SHOper(OpType::REG, SHReg(SGR), 0, false, false, false, 0, 4),
                SHOper(OpType::REG, SHReg(R0 + ((insn & 0xf00) >> 0x8)), 0, true, false, false, -4, 4)
            },
            false,
            2,
            addr
        );
    }

    if ((insn & 0xf0ff) == 0x0032) {
        return SHInsn(
            SHOpCode::op_stc,
            {
                {InstructionToken, "stc"},
                {TextToken, " "},
                {RegisterToken, "SSR"},
                {OperandSeparatorToken, ", "},
                {RegisterToken, "R" + std::to_string(((insn & 0xf00) >> 0x8)) }
            },
            {
                SHOper(OpType::REG, SHReg(SSR), 0, false, false, false, 0, 4),
                SHOper(OpType::REG, SHReg(R0 + ((insn & 0xf00) >> 0x8)), 0, false, false, false, 0, 4)
            },
            false,
            2,
            addr
        );
    }

    if ((insn & 0xf0ff) == 0x4033) {
        return SHInsn(
            SHOpCode::op_stc_l,
            {
                {InstructionToken, "stc.l"},
                {TextToken, " "},
                {RegisterToken, "SSR"},
                {OperandSeparatorToken, ", "},
                {TextToken, "@-"},
                {RegisterToken, "R" + std::to_string(((insn & 0xf00) >> 0x8)) }
            },
            {
                SHOper(OpType::REG, SHReg(SSR), 0, false, false, false, 0, 4),
                SHOper(OpType::REG, SHReg(R0 + ((insn & 0xf00) >> 0x8)), 0, true, false, false, -4, 4)
            },
            false,
            2,
            addr
        );
    }

    if ((insn & 0xf0ff) == 0x0042) {
        return SHInsn(
            SHOpCode::op_stc,
            {
                {InstructionToken, "stc"},
                {TextToken, " "},
                {RegisterToken, "SPC"},
                {OperandSeparatorToken, ", "},
                {RegisterToken, "R" + std::to_string(((insn & 0xf00) >> 0x8)) }
            },
            {
                SHOper(OpType::REG, SHReg(SPC), 0, false, false, false, 0, 4),
                SHOper(OpType::REG, SHReg(R0 + ((insn & 0xf00) >> 0x8)), 0, false, false, false, 0, 4)
            },
            false,
            2,
            addr
        );
    }

    if ((insn & 0xf0ff) == 0x4043) {
        return SHInsn(
            SHOpCode::op_stc_l,
            {
                {InstructionToken, "stc.l"},
                {TextToken, " "},
                {RegisterToken, "SPC"},
                {OperandSeparatorToken, ", "},
                {TextToken, "@-"},
                {RegisterToken, "R" + std::to_string(((insn & 0xf00) >> 0x8)) }
            },
            {
                SHOper(OpType::REG, SHReg(SPC), 0, false, false, false, 0, 4),
                SHOper(OpType::REG, SHReg(R0 + ((insn & 0xf00) >> 0x8)), 0, true, false, false, -4, 4)
            },
            false,
            2,
            addr
        );
    }

    if ((insn & 0xf0ff) == 0x00fa) {
        return SHInsn(
            SHOpCode::op_stc,
            {
                {InstructionToken, "stc"},
                {TextToken, " "},
                {RegisterToken, "DBR"},
                {OperandSeparatorToken, ", "},
                {RegisterToken, "R" + std::to_string(((insn & 0xf00) >> 0x8)) }
            },
            {
                SHOper(OpType::REG, SHReg(DBR), 0, false, false, false, 0, 4),
                SHOper(OpType::REG, SHReg(R0 + ((insn & 0xf00) >> 0x8)), 0, false, false, false, 0, 4)
            },
            false,
            2,
            addr
        );
    }

    if ((insn & 0xf0ff) == 0x40f2) {
        return SHInsn(
            SHOpCode::op_stc_l,
            {
                {InstructionToken, "stc.l"},
                {TextToken, " "},
                {RegisterToken, "DBR"},
                {OperandSeparatorToken, ", "},
                {TextToken, "@-"},
                {RegisterToken, "R" + std::to_string(((insn & 0xf00) >> 0x8)) }
            },
            {
                SHOper(OpType::REG, SHReg(DBR), 0, false, false, false, 0, 4),
                SHOper(OpType::REG, SHReg(R0 + ((insn & 0xf00) >> 0x8)), 0, true, false, false, -4, 4)
            },
            false,
            2,
            addr
        );
    }

    if ((insn & 0xf0ff) == 0x0082) {
        return SHInsn(
            SHOpCode::op_stc,
            {
                {InstructionToken, "stc"},
                {TextToken, " "},
                {RegisterToken, "R" + std::to_string(((insn & 0x70) >> 0x4)) + "_BANK" },
                {OperandSeparatorToken, ", "},
                {RegisterToken, "R" + std::to_string(((insn & 0xf00) >> 0x8)) }
            },
            {
                SHOper(OpType::REG, SHReg(R0_BANK + ((insn & 0x70) >> 0x4)), 0, false, false, false, 0, 4),
                SHOper(OpType::REG, SHReg(R0 + ((insn & 0xf00) >> 0x8)), 0, false, false, false, 0, 4)
            },
            false,
            2,
            addr
        );
    }

    if ((insn & 0xf0ff) == 0x4083) {
        return SHInsn(
            SHOpCode::op_stc_l,
            {
                {InstructionToken, "stc.l"},
                {TextToken, " "},
                {RegisterToken, "R" + std::to_string(((insn & 0x70) >> 0x4)) + "_BANK" },
                {OperandSeparatorToken, ", "},
                {TextToken, "@-"},
                {RegisterToken, "R" + std::to_string(((insn & 0xf00) >> 0x8)) }
            },
            {
                SHOper(OpType::REG, SHReg(R0_BANK + ((insn & 0x70) >> 0x4)), 0, false, false, false, 0, 4),
                SHOper(OpType::REG, SHReg(R0 + ((insn & 0xf00) >> 0x8)), 0, true, false, false, -4, 4)
            },
            false,
            2,
            addr
        );
    }

    if ((insn & 0xf0ff) == 0x000a) {
        return SHInsn(
            SHOpCode::op_sts,
            {
                {InstructionToken, "sts"},
                {TextToken, " "},
                {RegisterToken, "MACH"},
                {OperandSeparatorToken, ", "},
                {RegisterToken, "R" + std::to_string(((insn & 0xf00) >> 0x8)) }
            },
            {
                SHOper(OpType::REG, SHReg(MACH), 0, false, false, false, 0, 4),
                SHOper(OpType::REG, SHReg(R0 + ((insn & 0xf00) >> 0x8)), 0, false, false, false, 0, 4)
            },
            false,
            2,
            addr
        );
    }

    if ((insn & 0xf0ff) == 0x4002) {
        return SHInsn(
            SHOpCode::op_sts_l,
            {
                {InstructionToken, "sts.l"},
                {TextToken, " "},
                {RegisterToken, "MACH"},
                {OperandSeparatorToken, ", "},
                {TextToken, "@-"},
                {RegisterToken, "R" + std::to_string(((insn & 0xf00) >> 0x8)) }
            },
            {
                SHOper(OpType::REG, SHReg(MACH), 0, false, false, false, 0, 4),
                SHOper(OpType::REG, SHReg(R0 + ((insn & 0xf00) >> 0x8)), 0, true, false, false, -4, 4)
            },
            false,
            2,
            addr
        );
    }

    if ((insn & 0xf0ff) == 0x001a) {
        return SHInsn(
            SHOpCode::op_sts,
            {
                {InstructionToken, "sts"},
                {TextToken, " "},
                {RegisterToken, "MACL"},
                {OperandSeparatorToken, ", "},
                {RegisterToken, "R" + std::to_string(((insn & 0xf00) >> 0x8)) }
            },
            {
                SHOper(OpType::REG, SHReg(MACL), 0, false, false, false, 0, 4),
                SHOper(OpType::REG, SHReg(R0 + ((insn & 0xf00) >> 0x8)), 0, false, false, false, 0, 4)
            },
            false,
            2,
            addr
        );
    }

    if ((insn & 0xf0ff) == 0x4012) {
        return SHInsn(
            SHOpCode::op_sts_l,
            {
                {InstructionToken, "sts.l"},
                {TextToken, " "},
                {RegisterToken, "MACL"},
                {OperandSeparatorToken, ", "},
                {TextToken, "@-"},
                {RegisterToken, "R" + std::to_string(((insn & 0xf00) >> 0x8)) }
            },
            {
                SHOper(OpType::REG, SHReg(MACL), 0, false, false, false, 0, 4),
                SHOper(OpType::REG, SHReg(R0 + ((insn & 0xf00) >> 0x8)), 0, true, false, false, -4, 4)
            },
            false,
            2,
            addr
        );
    }

    if ((insn & 0xf0ff) == 0x002a) {
        return SHInsn(
            SHOpCode::op_sts,
            {
                {InstructionToken, "sts"},
                {TextToken, " "},
                {RegisterToken, "PR"},
                {OperandSeparatorToken, ", "},
                {RegisterToken, "R" + std::to_string(((insn & 0xf00) >> 0x8)) }
            },
            {
                SHOper(OpType::REG, SHReg(PR), 0, false, false, false, 0, 4),
                SHOper(OpType::REG, SHReg(R0 + ((insn & 0xf00) >> 0x8)), 0, false, false, false, 0, 4)
            },
            false,
            2,
            addr
        );
    }

    if ((insn & 0xf0ff) == 0x4022) {
        return SHInsn(
            SHOpCode::op_sts_l,
            {
                {InstructionToken, "sts.l"},
                {TextToken, " "},
                {RegisterToken, "PR"},
                {OperandSeparatorToken, ", "},
                {TextToken, "@-"},
                {RegisterToken, "R" + std::to_string(((insn & 0xf00) >> 0x8)) }
            },
            {
                SHOper(OpType::REG, SHReg(PR), 0, false, false, false, 0, 4),
                SHOper(OpType::REG, SHReg(R0 + ((insn & 0xf00) >> 0x8)), 0, true, false, false, -4, 4)
            },
            false,
            2,
            addr
        );
    }

    if ((insn & 0xf0ff) == 0x006a) {
        return SHInsn(
            SHOpCode::op_sts,
            {
                {InstructionToken, "sts"},
                {TextToken, " "},
                {RegisterToken, "DSR"},
                {OperandSeparatorToken, ", "},
                {RegisterToken, "R" + std::to_string(((insn & 0xf00) >> 0x8)) }
            },
            {
                SHOper(OpType::REG, SHReg(DSR), 0, false, false, false, 0, 4),
                SHOper(OpType::REG, SHReg(R0 + ((insn & 0xf00) >> 0x8)), 0, false, false, false, 0, 4)
            },
            false,
            2,
            addr
        );
    }

    if ((insn & 0xf0ff) == 0x4062) {
        return SHInsn(
            SHOpCode::op_sts_l,
            {
                {InstructionToken, "sts.l"},
                {TextToken, " "},
                {RegisterToken, "DSR"},
                {OperandSeparatorToken, ", "},
                {TextToken, "@-"},
                {RegisterToken, "R" + std::to_string(((insn & 0xf00) >> 0x8)) }
            },
            {
                SHOper(OpType::REG, SHReg(DSR), 0, false, false, false, 0, 4),
                SHOper(OpType::REG, SHReg(R0 + ((insn & 0xf00) >> 0x8)), 0, true, false, false, -4, 4)
            },
            false,
            2,
            addr
        );
    }

    if ((insn & 0xf0ff) == 0x007a) {
        return SHInsn(
            SHOpCode::op_sts,
            {
                {InstructionToken, "sts"},
                {TextToken, " "},
                {RegisterToken, "A0"},
                {OperandSeparatorToken, ", "},
                {RegisterToken, "R" + std::to_string(((insn & 0xf00) >> 0x8)) }
            },
            {
                SHOper(OpType::REG, SHReg(A0), 0, false, false, false, 0, 4),
                SHOper(OpType::REG, SHReg(R0 + ((insn & 0xf00) >> 0x8)), 0, false, false, false, 0, 4)
            },
            false,
            2,
            addr
        );
    }

    if ((insn & 0xf0ff) == 0x4062) {
        return SHInsn(
            SHOpCode::op_sts_l,
            {
                {InstructionToken, "sts.l"},
                {TextToken, " "},
                {RegisterToken, "A0"},
                {OperandSeparatorToken, ", "},
                {TextToken, "@-"},
                {RegisterToken, "R" + std::to_string(((insn & 0xf00) >> 0x8)) }
            },
            {
                SHOper(OpType::REG, SHReg(A0), 0, false, false, false, 0, 4),
                SHOper(OpType::REG, SHReg(R0 + ((insn & 0xf00) >> 0x8)), 0, true, false, false, -4, 4)
            },
            false,
            2,
            addr
        );
    }

    if ((insn & 0xf0ff) == 0x008a) {
        return SHInsn(
            SHOpCode::op_sts,
            {
                {InstructionToken, "sts"},
                {TextToken, " "},
                {RegisterToken, "X0"},
                {OperandSeparatorToken, ", "},
                {RegisterToken, "R" + std::to_string(((insn & 0xf00) >> 0x8)) }
            },
            {
                SHOper(OpType::REG, SHReg(X0), 0, false, false, false, 0, 4),
                SHOper(OpType::REG, SHReg(R0 + ((insn & 0xf00) >> 0x8)), 0, false, false, false, 0, 4)
            },
            false,
            2,
            addr
        );
    }

    if ((insn & 0xf0ff) == 0x4082) {
        return SHInsn(
            SHOpCode::op_sts_l,
            {
                {InstructionToken, "sts.l"},
                {TextToken, " "},
                {RegisterToken, "X0"},
                {OperandSeparatorToken, ", "},
                {TextToken, "@-"},
                {RegisterToken, "R" + std::to_string(((insn & 0xf00) >> 0x8)) }
            },
            {
                SHOper(OpType::REG, SHReg(X0), 0, false, false, false, 0, 4),
                SHOper(OpType::REG, SHReg(R0 + ((insn & 0xf00) >> 0x8)), 0, true, false, false, -4, 4)
            },
            false,
            2,
            addr
        );
    }

    if ((insn & 0xf0ff) == 0x009a) {
        return SHInsn(
            SHOpCode::op_sts,
            {
                {InstructionToken, "sts"},
                {TextToken, " "},
                {RegisterToken, "X1"},
                {OperandSeparatorToken, ", "},
                {RegisterToken, "R" + std::to_string(((insn & 0xf00) >> 0x8)) }
            },
            {
                SHOper(OpType::REG, SHReg(X1), 0, false, false, false, 0, 4),
                SHOper(OpType::REG, SHReg(R0 + ((insn & 0xf00) >> 0x8)), 0, false, false, false, 0, 4)
            },
            false,
            2,
            addr
        );
    }

    if ((insn & 0xf0ff) == 0x4092) {
        return SHInsn(
            SHOpCode::op_sts_l,
            {
                {InstructionToken, "sts.l"},
                {TextToken, " "},
                {RegisterToken, "X1"},
                {OperandSeparatorToken, ", "},
                {TextToken, "@-"},
                {RegisterToken, "R" + std::to_string(((insn & 0xf00) >> 0x8)) }
            },
            {
                SHOper(OpType::REG, SHReg(X1), 0, false, false, false, 0, 4),
                SHOper(OpType::REG, SHReg(R0 + ((insn & 0xf00) >> 0x8)), 0, true, false, false, -4, 4)
            },
            false,
            2,
            addr
        );
    }

    if ((insn & 0xf0ff) == 0x00aa) {
        return SHInsn(
            SHOpCode::op_sts,
            {
                {InstructionToken, "sts"},
                {TextToken, " "},
                {RegisterToken, "Y0"},
                {OperandSeparatorToken, ", "},
                {RegisterToken, "R" + std::to_string(((insn & 0xf00) >> 0x8)) }
            },
            {
                SHOper(OpType::REG, SHReg(Y0), 0, false, false, false, 0, 4),
                SHOper(OpType::REG, SHReg(R0 + ((insn & 0xf00) >> 0x8)), 0, false, false, false, 0, 4)
            },
            false,
            2,
            addr
        );
    }

    if ((insn & 0xf0ff) == 0x40a2) {
        return SHInsn(
            SHOpCode::op_sts_l,
            {
                {InstructionToken, "sts.l"},
                {TextToken, " "},
                {RegisterToken, "Y0"},
                {OperandSeparatorToken, ", "},
                {TextToken, "@-"},
                {RegisterToken, "R" + std::to_string(((insn & 0xf00) >> 0x8)) }
            },
            {
                SHOper(OpType::REG, SHReg(Y0), 0, false, false, false, 0, 4),
                SHOper(OpType::REG, SHReg(R0 + ((insn & 0xf00) >> 0x8)), 0, true, false, false, -4, 4)
            },
            false,
            2,
            addr
        );
    }

    if ((insn & 0xf0ff) == 0x00ba) {
        return SHInsn(
            SHOpCode::op_sts,
            {
                {InstructionToken, "sts"},
                {TextToken, " "},
                {RegisterToken, "Y1"},
                {OperandSeparatorToken, ", "},
                {RegisterToken, "R" + std::to_string(((insn & 0xf00) >> 0x8)) }
            },
            {
                SHOper(OpType::REG, SHReg(Y1), 0, false, false, false, 0, 4),
                SHOper(OpType::REG, SHReg(R0 + ((insn & 0xf00) >> 0x8)), 0, false, false, false, 0, 4)
            },
            false,
            2,
            addr
        );
    }

    if ((insn & 0xf0ff) == 0x40b2) {
        return SHInsn(
            SHOpCode::op_sts_l,
            {
                {InstructionToken, "sts.l"},
                {TextToken, " "},
                {RegisterToken, "Y1"},
                {OperandSeparatorToken, ", "},
                {TextToken, "@-"},
                {RegisterToken, "R" + std::to_string(((insn & 0xf00) >> 0x8)) }
            },
            {
                SHOper(OpType::REG, SHReg(Y1), 0, false, false, false, 0, 4),
                SHOper(OpType::REG, SHReg(R0 + ((insn & 0xf00) >> 0x8)), 0, true, false, false, -4, 4)
            },
            false,
            2,
            addr
        );
    }

    if ((insn & 0xffff) == 0x00ab) {
        return SHInsn(
            SHOpCode::op_synco,
            {
                {InstructionToken, "synco"},
                {TextToken, " "}
            },
            {
                
            },
            false,
            2,
            addr
        );
    }

    if ((insn & 0xff00) == 0xc300) {
        return SHInsn(
            SHOpCode::op_trapa,
            {
                {InstructionToken, "trapa"},
                {TextToken, " "},
                {PossibleAddressToken, int_to_hex((insn & 0xff))}
            },
            {
                SHOper(OpType::IMM, SHReg::InvalidReg, (insn & 0xff), false, false, false, 0, 1)
            },
            false,
            2,
            addr
        );
    }

    if ((insn & 0xf00f) == 0xf00c) {
        return SHInsn(
            SHOpCode::op_fmov,
            {
                {InstructionToken, "fmov"},
                {TextToken, " "},
                {RegisterToken, "FR" + std::to_string(((insn & 0xf0) >> 0x4)) },
                {OperandSeparatorToken, ", "},
                {RegisterToken, "FR" + std::to_string(((insn & 0xf00) >> 0x8)) }
            },
            {
                SHOper(OpType::REG, SHReg(FR0 + ((insn & 0xf0) >> 0x4)), 0, false, false, false, 0, 4),
                SHOper(OpType::REG, SHReg(FR0 + ((insn & 0xf00) >> 0x8)), 0, false, false, false, 0, 4)
            },
            false,
            2,
            addr
        );
    }

    if ((insn & 0xf00f) == 0xf008) {
        return SHInsn(
            SHOpCode::op_fmov_s,
            {
                {InstructionToken, "fmov.s"},
                {TextToken, " "},
                {TextToken, "@"},
                {RegisterToken, "R" + std::to_string(((insn & 0xf0) >> 0x4)) },
                {OperandSeparatorToken, ", "},
                {RegisterToken, "FR" + std::to_string(((insn & 0xf00) >> 0x8)) }
            },
            {
                SHOper(OpType::REG, SHReg(R0 + ((insn & 0xf0) >> 0x4)), 0, true, false, false, 0, 4),
                SHOper(OpType::REG, SHReg(FR0 + ((insn & 0xf00) >> 0x8)), 0, false, false, false, 0, 4)
            },
            false,
            2,
            addr
        );
    }

    if ((insn & 0xf00f) == 0xf00a) {
        return SHInsn(
            SHOpCode::op_fmov_s,
            {
                {InstructionToken, "fmov.s"},
                {TextToken, " "},
                {RegisterToken, "FR" + std::to_string(((insn & 0xf0) >> 0x4)) },
                {OperandSeparatorToken, ", "},
                {TextToken, "@"},
                {RegisterToken, "R" + std::to_string(((insn & 0xf00) >> 0x8)) }
            },
            {
                SHOper(OpType::REG, SHReg(FR0 + ((insn & 0xf0) >> 0x4)), 0, false, false, false, 0, 4),
                SHOper(OpType::REG, SHReg(R0 + ((insn & 0xf00) >> 0x8)), 0, true, false, false, 0, 4)
            },
            false,
            2,
            addr
        );
    }

    if ((insn & 0xf00f) == 0xf009) {
        return SHInsn(
            SHOpCode::op_fmov_s,
            {
                {InstructionToken, "fmov.s"},
                {TextToken, " "},
                {TextToken, "@"},
                {RegisterToken, "R" + std::to_string(((insn & 0xf0) >> 0x4)) },
                {TextToken, "+"},
                {OperandSeparatorToken, ", "},
                {RegisterToken, "FR" + std::to_string(((insn & 0xf00) >> 0x8)) }
            },
            {
                SHOper(OpType::REG, SHReg(R0 + ((insn & 0xf0) >> 0x4)), 0, true, false, false, 4, 4),
                SHOper(OpType::REG, SHReg(FR0 + ((insn & 0xf00) >> 0x8)), 0, false, false, false, 0, 4)
            },
            false,
            2,
            addr
        );
    }

    if ((insn & 0xf00f) == 0xf00b) {
        return SHInsn(
            SHOpCode::op_fmov_s,
            {
                {InstructionToken, "fmov.s"},
                {TextToken, " "},
                {RegisterToken, "FR" + std::to_string(((insn & 0xf0) >> 0x4)) },
                {OperandSeparatorToken, ", "},
                {TextToken, "@-"},
                {RegisterToken, "R" + std::to_string(((insn & 0xf00) >> 0x8)) }
            },
            {
                SHOper(OpType::REG, SHReg(FR0 + ((insn & 0xf0) >> 0x4)), 0, false, false, false, 0, 4),
                SHOper(OpType::REG, SHReg(R0 + ((insn & 0xf00) >> 0x8)), 0, true, false, false, -4, 4)
            },
            false,
            2,
            addr
        );
    }

    if ((insn & 0xf00f) == 0xf006) {
        return SHInsn(
            SHOpCode::op_fmov_s,
            {
                {InstructionToken, "fmov.s"},
                {TextToken, " "},
                {TextToken, "@("},
                {RegisterToken, "R0"},
                {OperandSeparatorToken, ", "},
                {RegisterToken, "R" + std::to_string(((insn & 0xf0) >> 0x4)) },
                {TextToken, ")"},
                {OperandSeparatorToken, ", "},
                {RegisterToken, "FR" + std::to_string(((insn & 0xf00) >> 0x8)) }
            },
            {
                SHOper(OpType::REG, SHReg(R0), 0, true, true, false, 0, 4),
                SHOper(OpType::REG, SHReg(R0 + ((insn & 0xf0) >> 0x4)), 0, false, false, false, 0, 4),
                SHOper(OpType::REG, SHReg(FR0 + ((insn & 0xf00) >> 0x8)), 0, false, false, false, 0, 4)
            },
            false,
            2,
            addr
        );
    }

    if ((insn & 0xf00f) == 0xf007) {
        return SHInsn(
            SHOpCode::op_fmov_s,
            {
                {InstructionToken, "fmov.s"},
                {TextToken, " "},
                {RegisterToken, "FR" + std::to_string(((insn & 0xf0) >> 0x4)) },
                {OperandSeparatorToken, ", "},
                {TextToken, "@("},
                {RegisterToken, "R0"},
                {OperandSeparatorToken, ", "},
                {RegisterToken, "R" + std::to_string(((insn & 0xf00) >> 0x8)) },
                {TextToken, ")"}
            },
            {
                SHOper(OpType::REG, SHReg(FR0 + ((insn & 0xf0) >> 0x4)), 0, false, false, false, 0, 4),
                SHOper(OpType::REG, SHReg(R0), 0, true, true, false, 0, 4),
                SHOper(OpType::REG, SHReg(R0 + ((insn & 0xf00) >> 0x8)), 0, false, false, false, 0, 4)
            },
            false,
            2,
            addr
        );
    }

    if ((insn & 0xf00f) == 0xf00c) {
        return SHInsn(
            SHOpCode::op_fmov,
            {
                {InstructionToken, "fmov"},
                {TextToken, " "},
                {RegisterToken, "DR" + std::to_string(((insn & 0xf0) >> 0x4)) },
                {OperandSeparatorToken, ", "},
                {RegisterToken, "DR" + std::to_string(((insn & 0xf00) >> 0x8)) }
            },
            {
                SHOper(OpType::REG, SHReg(DR0 + ((insn & 0xf0) >> 0x4)), 0, false, false, false, 0, 4),
                SHOper(OpType::REG, SHReg(DR0 + ((insn & 0xf00) >> 0x8)), 0, false, false, false, 0, 4)
            },
            false,
            2,
            addr
        );
    }

    if ((insn & 0xf00f) == 0xf00c) {
        return SHInsn(
            SHOpCode::op_fmov,
            {
                {InstructionToken, "fmov"},
                {TextToken, " "},
                {RegisterToken, "DR" + std::to_string(((insn & 0xf0) >> 0x4)) },
                {OperandSeparatorToken, ", "},
                {RegisterToken, "DR" + std::to_string(((insn & 0xf00) >> 0x8)) }
            },
            {
                SHOper(OpType::REG, SHReg(DR0 + ((insn & 0xf0) >> 0x4)), 0, false, false, false, 0, 4),
                SHOper(OpType::REG, SHReg(DR0 + ((insn & 0xf00) >> 0x8)), 0, false, false, false, 0, 4)
            },
            false,
            2,
            addr
        );
    }

    if ((insn & 0xf00f) == 0xf00c) {
        return SHInsn(
            SHOpCode::op_fmov,
            {
                {InstructionToken, "fmov"},
                {TextToken, " "},
                {RegisterToken, "XD" + std::to_string(((insn & 0xf0) >> 0x4)) },
                {OperandSeparatorToken, ", "},
                {RegisterToken, "DR" + std::to_string(((insn & 0xf00) >> 0x8)) }
            },
            {
                SHOper(OpType::REG, SHReg(XD0 + ((insn & 0xf0) >> 0x4)), 0, false, false, false, 0, 4),
                SHOper(OpType::REG, SHReg(DR0 + ((insn & 0xf00) >> 0x8)), 0, false, false, false, 0, 4)
            },
            false,
            2,
            addr
        );
    }

    if ((insn & 0xf00f) == 0xf00c) {
        return SHInsn(
            SHOpCode::op_fmov,
            {
                {InstructionToken, "fmov"},
                {TextToken, " "},
                {RegisterToken, "XD" + std::to_string(((insn & 0xf0) >> 0x4)) },
                {OperandSeparatorToken, ", "},
                {RegisterToken, "DR" + std::to_string(((insn & 0xf00) >> 0x8)) }
            },
            {
                SHOper(OpType::REG, SHReg(XD0 + ((insn & 0xf0) >> 0x4)), 0, false, false, false, 0, 4),
                SHOper(OpType::REG, SHReg(DR0 + ((insn & 0xf00) >> 0x8)), 0, false, false, false, 0, 4)
            },
            false,
            2,
            addr
        );
    }

    if ((insn & 0xf00f) == 0xf008) {
        return SHInsn(
            SHOpCode::op_fmov_d,
            {
                {InstructionToken, "fmov.d"},
                {TextToken, " "},
                {TextToken, "@"},
                {RegisterToken, "R" + std::to_string(((insn & 0xf0) >> 0x4)) },
                {OperandSeparatorToken, ", "},
                {RegisterToken, "DR" + std::to_string(((insn & 0xf00) >> 0x8)) }
            },
            {
                SHOper(OpType::REG, SHReg(R0 + ((insn & 0xf0) >> 0x4)), 0, true, false, false, 0, 4),
                SHOper(OpType::REG, SHReg(DR0 + ((insn & 0xf00) >> 0x8)), 0, false, false, false, 0, 4)
            },
            false,
            2,
            addr
        );
    }

    if ((insn & 0xf00f) == 0xf008) {
        return SHInsn(
            SHOpCode::op_fmov_d,
            {
                {InstructionToken, "fmov.d"},
                {TextToken, " "},
                {TextToken, "@"},
                {RegisterToken, "R" + std::to_string(((insn & 0xf0) >> 0x4)) },
                {OperandSeparatorToken, ", "},
                {RegisterToken, "DR" + std::to_string(((insn & 0xf00) >> 0x8)) }
            },
            {
                SHOper(OpType::REG, SHReg(R0 + ((insn & 0xf0) >> 0x4)), 0, true, false, false, 0, 4),
                SHOper(OpType::REG, SHReg(DR0 + ((insn & 0xf00) >> 0x8)), 0, false, false, false, 0, 4)
            },
            false,
            2,
            addr
        );
    }

    if ((insn & 0xf00f) == 0xf00a) {
        return SHInsn(
            SHOpCode::op_fmov_d,
            {
                {InstructionToken, "fmov.d"},
                {TextToken, " "},
                {RegisterToken, "DR" + std::to_string(((insn & 0xf0) >> 0x4)) },
                {OperandSeparatorToken, ", "},
                {TextToken, "@"},
                {RegisterToken, "R" + std::to_string(((insn & 0xf00) >> 0x8)) }
            },
            {
                SHOper(OpType::REG, SHReg(DR0 + ((insn & 0xf0) >> 0x4)), 0, false, false, false, 0, 4),
                SHOper(OpType::REG, SHReg(R0 + ((insn & 0xf00) >> 0x8)), 0, true, false, false, 0, 4)
            },
            false,
            2,
            addr
        );
    }

    if ((insn & 0xf00f) == 0xf00a) {
        return SHInsn(
            SHOpCode::op_fmov_d,
            {
                {InstructionToken, "fmov.d"},
                {TextToken, " "},
                {RegisterToken, "XD" + std::to_string(((insn & 0xf0) >> 0x4)) },
                {OperandSeparatorToken, ", "},
                {TextToken, "@"},
                {RegisterToken, "R" + std::to_string(((insn & 0xf00) >> 0x8)) }
            },
            {
                SHOper(OpType::REG, SHReg(XD0 + ((insn & 0xf0) >> 0x4)), 0, false, false, false, 0, 4),
                SHOper(OpType::REG, SHReg(R0 + ((insn & 0xf00) >> 0x8)), 0, true, false, false, 0, 4)
            },
            false,
            2,
            addr
        );
    }

    if ((insn & 0xf00f) == 0xf009) {
        return SHInsn(
            SHOpCode::op_fmov_d,
            {
                {InstructionToken, "fmov.d"},
                {TextToken, " "},
                {TextToken, "@"},
                {RegisterToken, "R" + std::to_string(((insn & 0xf0) >> 0x4)) },
                {TextToken, "+"},
                {OperandSeparatorToken, ", "},
                {RegisterToken, "DR" + std::to_string(((insn & 0xf00) >> 0x8)) }
            },
            {
                SHOper(OpType::REG, SHReg(R0 + ((insn & 0xf0) >> 0x4)), 0, true, false, false, 8, 4),
                SHOper(OpType::REG, SHReg(DR0 + ((insn & 0xf00) >> 0x8)), 0, false, false, false, 0, 4)
            },
            false,
            2,
            addr
        );
    }

    if ((insn & 0xf00f) == 0xf009) {
        return SHInsn(
            SHOpCode::op_fmov_d,
            {
                {InstructionToken, "fmov.d"},
                {TextToken, " "},
                {TextToken, "@"},
                {RegisterToken, "R" + std::to_string(((insn & 0xf0) >> 0x4)) },
                {TextToken, "+"},
                {OperandSeparatorToken, ", "},
                {RegisterToken, "DR" + std::to_string(((insn & 0xf00) >> 0x8)) }
            },
            {
                SHOper(OpType::REG, SHReg(R0 + ((insn & 0xf0) >> 0x4)), 0, true, false, false, 8, 4),
                SHOper(OpType::REG, SHReg(DR0 + ((insn & 0xf00) >> 0x8)), 0, false, false, false, 0, 4)
            },
            false,
            2,
            addr
        );
    }

    if ((insn & 0xf00f) == 0xf00b) {
        return SHInsn(
            SHOpCode::op_fmov_d,
            {
                {InstructionToken, "fmov.d"},
                {TextToken, " "},
                {RegisterToken, "DR" + std::to_string(((insn & 0xf0) >> 0x4)) },
                {OperandSeparatorToken, ", "},
                {TextToken, "@-"},
                {RegisterToken, "R" + std::to_string(((insn & 0xf00) >> 0x8)) }
            },
            {
                SHOper(OpType::REG, SHReg(DR0 + ((insn & 0xf0) >> 0x4)), 0, false, false, false, 0, 4),
                SHOper(OpType::REG, SHReg(R0 + ((insn & 0xf00) >> 0x8)), 0, true, false, false, -8, 4)
            },
            false,
            2,
            addr
        );
    }

    if ((insn & 0xf00f) == 0xf00b) {
        return SHInsn(
            SHOpCode::op_fmov_d,
            {
                {InstructionToken, "fmov.d"},
                {TextToken, " "},
                {RegisterToken, "XD" + std::to_string(((insn & 0xf0) >> 0x4)) },
                {OperandSeparatorToken, ", "},
                {TextToken, "@-"},
                {RegisterToken, "R" + std::to_string(((insn & 0xf00) >> 0x8)) }
            },
            {
                SHOper(OpType::REG, SHReg(XD0 + ((insn & 0xf0) >> 0x4)), 0, false, false, false, 0, 4),
                SHOper(OpType::REG, SHReg(R0 + ((insn & 0xf00) >> 0x8)), 0, true, false, false, -8, 4)
            },
            false,
            2,
            addr
        );
    }

    if ((insn & 0xf00f) == 0xf006) {
        return SHInsn(
            SHOpCode::op_fmov_d,
            {
                {InstructionToken, "fmov.d"},
                {TextToken, " "},
                {TextToken, "@("},
                {RegisterToken, "R0"},
                {OperandSeparatorToken, ", "},
                {RegisterToken, "R" + std::to_string(((insn & 0xf0) >> 0x4)) },
                {TextToken, ")"},
                {OperandSeparatorToken, ", "},
                {RegisterToken, "DR" + std::to_string(((insn & 0xf00) >> 0x8)) }
            },
            {
                SHOper(OpType::REG, SHReg(R0), 0, true, true, false, 0, 4),
                SHOper(OpType::REG, SHReg(R0 + ((insn & 0xf0) >> 0x4)), 0, false, false, false, 0, 4),
                SHOper(OpType::REG, SHReg(DR0 + ((insn & 0xf00) >> 0x8)), 0, false, false, false, 0, 4)
            },
            false,
            2,
            addr
        );
    }

    if ((insn & 0xf00f) == 0xf006) {
        return SHInsn(
            SHOpCode::op_fmov_d,
            {
                {InstructionToken, "fmov.d"},
                {TextToken, " "},
                {TextToken, "@("},
                {RegisterToken, "R0"},
                {OperandSeparatorToken, ", "},
                {RegisterToken, "R" + std::to_string(((insn & 0xf0) >> 0x4)) },
                {TextToken, ")"},
                {OperandSeparatorToken, ", "},
                {RegisterToken, "DR" + std::to_string(((insn & 0xf00) >> 0x8)) }
            },
            {
                SHOper(OpType::REG, SHReg(R0), 0, true, true, false, 0, 4),
                SHOper(OpType::REG, SHReg(R0 + ((insn & 0xf0) >> 0x4)), 0, false, false, false, 0, 4),
                SHOper(OpType::REG, SHReg(DR0 + ((insn & 0xf00) >> 0x8)), 0, false, false, false, 0, 4)
            },
            false,
            2,
            addr
        );
    }

    if ((insn & 0xf00f) == 0xf007) {
        return SHInsn(
            SHOpCode::op_fmov_d,
            {
                {InstructionToken, "fmov.d"},
                {TextToken, " "},
                {RegisterToken, "DR" + std::to_string(((insn & 0xf0) >> 0x4)) },
                {OperandSeparatorToken, ", "},
                {TextToken, "@("},
                {RegisterToken, "R0"},
                {OperandSeparatorToken, ", "},
                {RegisterToken, "R" + std::to_string(((insn & 0xf00) >> 0x8)) },
                {TextToken, ")"}
            },
            {
                SHOper(OpType::REG, SHReg(DR0 + ((insn & 0xf0) >> 0x4)), 0, false, false, false, 0, 4),
                SHOper(OpType::REG, SHReg(R0), 0, true, true, false, 0, 4),
                SHOper(OpType::REG, SHReg(R0 + ((insn & 0xf00) >> 0x8)), 0, false, false, false, 0, 4)
            },
            false,
            2,
            addr
        );
    }

    if ((insn & 0xf00f) == 0xf007) {
        return SHInsn(
            SHOpCode::op_fmov_d,
            {
                {InstructionToken, "fmov.d"},
                {TextToken, " "},
                {RegisterToken, "XD" + std::to_string(((insn & 0xf0) >> 0x4)) },
                {OperandSeparatorToken, ", "},
                {TextToken, "@("},
                {RegisterToken, "R0"},
                {OperandSeparatorToken, ", "},
                {RegisterToken, "R" + std::to_string(((insn & 0xf00) >> 0x8)) },
                {TextToken, ")"}
            },
            {
                SHOper(OpType::REG, SHReg(XD0 + ((insn & 0xf0) >> 0x4)), 0, false, false, false, 0, 4),
                SHOper(OpType::REG, SHReg(R0), 0, true, true, false, 0, 4),
                SHOper(OpType::REG, SHReg(R0 + ((insn & 0xf00) >> 0x8)), 0, false, false, false, 0, 4)
            },
            false,
            2,
            addr
        );
    }

    if ((insn & 0xf0ff) == 0xf08d) {
        return SHInsn(
            SHOpCode::op_fldi0,
            {
                {InstructionToken, "fldi0"},
                {TextToken, " "},
                {RegisterToken, "FR" + std::to_string(((insn & 0xf00) >> 0x8)) }
            },
            {
                SHOper(OpType::REG, SHReg(FR0 + ((insn & 0xf00) >> 0x8)), 0, false, false, false, 0, 4)
            },
            false,
            2,
            addr
        );
    }

    if ((insn & 0xf0ff) == 0xf09d) {
        return SHInsn(
            SHOpCode::op_fldi1,
            {
                {InstructionToken, "fldi1"},
                {TextToken, " "},
                {RegisterToken, "FR" + std::to_string(((insn & 0xf00) >> 0x8)) }
            },
            {
                SHOper(OpType::REG, SHReg(FR0 + ((insn & 0xf00) >> 0x8)), 0, false, false, false, 0, 4)
            },
            false,
            2,
            addr
        );
    }

    if ((insn & 0xf0ff) == 0xf01d) {
        return SHInsn(
            SHOpCode::op_flds,
            {
                {InstructionToken, "flds"},
                {TextToken, " "},
                {RegisterToken, "FR" + std::to_string(((insn & 0xf00) >> 0x8)) },
                {OperandSeparatorToken, ", "},
                {RegisterToken, "FPUL"}
            },
            {
                SHOper(OpType::REG, SHReg(FR0 + ((insn & 0xf00) >> 0x8)), 0, false, false, false, 0, 4),
                SHOper(OpType::REG, SHReg(FPUL), 0, false, false, false, 0, 4)
            },
            false,
            2,
            addr
        );
    }

    if ((insn & 0xf0ff) == 0xf00d) {
        return SHInsn(
            SHOpCode::op_fsts,
            {
                {InstructionToken, "fsts"},
                {TextToken, " "},
                {RegisterToken, "FPUL"},
                {OperandSeparatorToken, ", "},
                {RegisterToken, "FR" + std::to_string(((insn & 0xf00) >> 0x8)) }
            },
            {
                SHOper(OpType::REG, SHReg(FPUL), 0, false, false, false, 0, 4),
                SHOper(OpType::REG, SHReg(FR0 + ((insn & 0xf00) >> 0x8)), 0, false, false, false, 0, 4)
            },
            false,
            2,
            addr
        );
    }

    if ((insn & 0xf0ff) == 0xf05d) {
        return SHInsn(
            SHOpCode::op_fabs,
            {
                {InstructionToken, "fabs"},
                {TextToken, " "},
                {RegisterToken, "FR" + std::to_string(((insn & 0xf00) >> 0x8)) }
            },
            {
                SHOper(OpType::REG, SHReg(FR0 + ((insn & 0xf00) >> 0x8)), 0, false, false, false, 0, 4)
            },
            false,
            2,
            addr
        );
    }

    if ((insn & 0xf0ff) == 0xf04d) {
        return SHInsn(
            SHOpCode::op_fneg,
            {
                {InstructionToken, "fneg"},
                {TextToken, " "},
                {RegisterToken, "FR" + std::to_string(((insn & 0xf00) >> 0x8)) }
            },
            {
                SHOper(OpType::REG, SHReg(FR0 + ((insn & 0xf00) >> 0x8)), 0, false, false, false, 0, 4)
            },
            false,
            2,
            addr
        );
    }

    if ((insn & 0xf00f) == 0xf000) {
        return SHInsn(
            SHOpCode::op_fadd,
            {
                {InstructionToken, "fadd"},
                {TextToken, " "},
                {RegisterToken, "FR" + std::to_string(((insn & 0xf0) >> 0x4)) },
                {OperandSeparatorToken, ", "},
                {RegisterToken, "FR" + std::to_string(((insn & 0xf00) >> 0x8)) }
            },
            {
                SHOper(OpType::REG, SHReg(FR0 + ((insn & 0xf0) >> 0x4)), 0, false, false, false, 0, 4),
                SHOper(OpType::REG, SHReg(FR0 + ((insn & 0xf00) >> 0x8)), 0, false, false, false, 0, 4)
            },
            false,
            2,
            addr
        );
    }

    if ((insn & 0xf00f) == 0xf001) {
        return SHInsn(
            SHOpCode::op_fsub,
            {
                {InstructionToken, "fsub"},
                {TextToken, " "},
                {RegisterToken, "FR" + std::to_string(((insn & 0xf0) >> 0x4)) },
                {OperandSeparatorToken, ", "},
                {RegisterToken, "FR" + std::to_string(((insn & 0xf00) >> 0x8)) }
            },
            {
                SHOper(OpType::REG, SHReg(FR0 + ((insn & 0xf0) >> 0x4)), 0, false, false, false, 0, 4),
                SHOper(OpType::REG, SHReg(FR0 + ((insn & 0xf00) >> 0x8)), 0, false, false, false, 0, 4)
            },
            false,
            2,
            addr
        );
    }

    if ((insn & 0xf00f) == 0xf002) {
        return SHInsn(
            SHOpCode::op_fmul,
            {
                {InstructionToken, "fmul"},
                {TextToken, " "},
                {RegisterToken, "FR" + std::to_string(((insn & 0xf0) >> 0x4)) },
                {OperandSeparatorToken, ", "},
                {RegisterToken, "FR" + std::to_string(((insn & 0xf00) >> 0x8)) }
            },
            {
                SHOper(OpType::REG, SHReg(FR0 + ((insn & 0xf0) >> 0x4)), 0, false, false, false, 0, 4),
                SHOper(OpType::REG, SHReg(FR0 + ((insn & 0xf00) >> 0x8)), 0, false, false, false, 0, 4)
            },
            false,
            2,
            addr
        );
    }

    if ((insn & 0xf00f) == 0xf00e) {
        return SHInsn(
            SHOpCode::op_fmac,
            {
                {InstructionToken, "fmac"},
                {TextToken, " "},
                {TextToken, "0"},
                {OperandSeparatorToken, ", "},
                {RegisterToken, "FR" + std::to_string(((insn & 0xf0) >> 0x4)) },
                {OperandSeparatorToken, ", "},
                {RegisterToken, "FR" + std::to_string(((insn & 0xf00) >> 0x8)) }
            },
            {
                SHOper(OpType::UNKNOWN, SHReg::InvalidReg, 0, false, false, false, 0, 0),
                SHOper(OpType::REG, SHReg(FR0 + ((insn & 0xf0) >> 0x4)), 0, false, false, false, 0, 4),
                SHOper(OpType::REG, SHReg(FR0 + ((insn & 0xf00) >> 0x8)), 0, false, false, false, 0, 4)
            },
            false,
            2,
            addr
        );
    }

    if ((insn & 0xf00f) == 0xf003) {
        return SHInsn(
            SHOpCode::op_fdiv,
            {
                {InstructionToken, "fdiv"},
                {TextToken, " "},
                {RegisterToken, "FR" + std::to_string(((insn & 0xf0) >> 0x4)) },
                {OperandSeparatorToken, ", "},
                {RegisterToken, "FR" + std::to_string(((insn & 0xf00) >> 0x8)) }
            },
            {
                SHOper(OpType::REG, SHReg(FR0 + ((insn & 0xf0) >> 0x4)), 0, false, false, false, 0, 4),
                SHOper(OpType::REG, SHReg(FR0 + ((insn & 0xf00) >> 0x8)), 0, false, false, false, 0, 4)
            },
            false,
            2,
            addr
        );
    }

    if ((insn & 0xf0ff) == 0xf06d) {
        return SHInsn(
            SHOpCode::op_fsqrt,
            {
                {InstructionToken, "fsqrt"},
                {TextToken, " "},
                {RegisterToken, "FR" + std::to_string(((insn & 0xf00) >> 0x8)) }
            },
            {
                SHOper(OpType::REG, SHReg(FR0 + ((insn & 0xf00) >> 0x8)), 0, false, false, false, 0, 4)
            },
            false,
            2,
            addr
        );
    }

    if ((insn & 0xf00f) == 0xf004) {
        return SHInsn(
            SHOpCode::op_fcmp_eq,
            {
                {InstructionToken, "fcmp/eq"},
                {TextToken, " "},
                {RegisterToken, "FR" + std::to_string(((insn & 0xf0) >> 0x4)) },
                {OperandSeparatorToken, ", "},
                {RegisterToken, "FR" + std::to_string(((insn & 0xf00) >> 0x8)) }
            },
            {
                SHOper(OpType::REG, SHReg(FR0 + ((insn & 0xf0) >> 0x4)), 0, false, false, false, 0, 4),
                SHOper(OpType::REG, SHReg(FR0 + ((insn & 0xf00) >> 0x8)), 0, false, false, false, 0, 4)
            },
            false,
            2,
            addr
        );
    }

    if ((insn & 0xf00f) == 0xf005) {
        return SHInsn(
            SHOpCode::op_fcmp_gt,
            {
                {InstructionToken, "fcmp/gt"},
                {TextToken, " "},
                {RegisterToken, "FR" + std::to_string(((insn & 0xf0) >> 0x4)) },
                {OperandSeparatorToken, ", "},
                {RegisterToken, "FR" + std::to_string(((insn & 0xf00) >> 0x8)) }
            },
            {
                SHOper(OpType::REG, SHReg(FR0 + ((insn & 0xf0) >> 0x4)), 0, false, false, false, 0, 4),
                SHOper(OpType::REG, SHReg(FR0 + ((insn & 0xf00) >> 0x8)), 0, false, false, false, 0, 4)
            },
            false,
            2,
            addr
        );
    }

    if ((insn & 0xf0ff) == 0xf02d) {
        return SHInsn(
            SHOpCode::op_float,
            {
                {InstructionToken, "float"},
                {TextToken, " "},
                {RegisterToken, "FPUL"},
                {OperandSeparatorToken, ", "},
                {RegisterToken, "FR" + std::to_string(((insn & 0xf00) >> 0x8)) }
            },
            {
                SHOper(OpType::REG, SHReg(FPUL), 0, false, false, false, 0, 4),
                SHOper(OpType::REG, SHReg(FR0 + ((insn & 0xf00) >> 0x8)), 0, false, false, false, 0, 4)
            },
            false,
            2,
            addr
        );
    }

    if ((insn & 0xf0ff) == 0xf03d) {
        return SHInsn(
            SHOpCode::op_ftrc,
            {
                {InstructionToken, "ftrc"},
                {TextToken, " "},
                {RegisterToken, "FR" + std::to_string(((insn & 0xf00) >> 0x8)) },
                {OperandSeparatorToken, ", "},
                {RegisterToken, "FPUL"}
            },
            {
                SHOper(OpType::REG, SHReg(FR0 + ((insn & 0xf00) >> 0x8)), 0, false, false, false, 0, 4),
                SHOper(OpType::REG, SHReg(FPUL), 0, false, false, false, 0, 4)
            },
            false,
            2,
            addr
        );
    }

    if ((insn & 0xf0ff) == 0xf0ed) {
        return SHInsn(
            SHOpCode::op_fipr,
            {
                {InstructionToken, "fipr"},
                {TextToken, " "},
                {RegisterToken, "FV" + std::to_string(((insn & 0x0) >> 0x0)) },
                {OperandSeparatorToken, ", "},
                {RegisterToken, "FV" + std::to_string(((insn & 0xf00) >> 0x8)) }
            },
            {
                SHOper(OpType::REG, SHReg(FV0 + ((insn & 0x0) >> 0x0)), 0, false, false, false, 0, 4),
                SHOper(OpType::REG, SHReg(FV0 + ((insn & 0xf00) >> 0x8)), 0, false, false, false, 0, 4)
            },
            false,
            2,
            addr
        );
    }

    if ((insn & 0xf0ff) == 0xf0fd) {
        return SHInsn(
            SHOpCode::op_ftrv,
            {
                {InstructionToken, "ftrv"},
                {TextToken, " "},
                {RegisterToken, "XMTRX"},
                {OperandSeparatorToken, ", "},
                {RegisterToken, "FV" + std::to_string(((insn & 0xf00) >> 0x8)) }
            },
            {
                SHOper(OpType::REG, SHReg(XMTRX), 0, false, false, false, 0, 4),
                SHOper(OpType::REG, SHReg(FV0 + ((insn & 0xf00) >> 0x8)), 0, false, false, false, 0, 4)
            },
            false,
            2,
            addr
        );
    }

    if ((insn & 0xf0ff) == 0xf07d) {
        return SHInsn(
            SHOpCode::op_fsrra,
            {
                {InstructionToken, "fsrra"},
                {TextToken, " "},
                {RegisterToken, "FR" + std::to_string(((insn & 0xf00) >> 0x8)) }
            },
            {
                SHOper(OpType::REG, SHReg(FR0 + ((insn & 0xf00) >> 0x8)), 0, false, false, false, 0, 4)
            },
            false,
            2,
            addr
        );
    }

    if ((insn & 0xf0ff) == 0xf0fd) {
        return SHInsn(
            SHOpCode::op_fsca,
            {
                {InstructionToken, "fsca"},
                {TextToken, " "},
                {RegisterToken, "FPUL"},
                {OperandSeparatorToken, ", "},
                {RegisterToken, "DR" + std::to_string(((insn & 0xf00) >> 0x8)) }
            },
            {
                SHOper(OpType::REG, SHReg(FPUL), 0, false, false, false, 0, 4),
                SHOper(OpType::REG, SHReg(DR0 + ((insn & 0xf00) >> 0x8)), 0, false, false, false, 0, 4)
            },
            false,
            2,
            addr
        );
    }

    if ((insn & 0xf0ff) == 0xf05d) {
        return SHInsn(
            SHOpCode::op_fabs,
            {
                {InstructionToken, "fabs"},
                {TextToken, " "},
                {RegisterToken, "DR" + std::to_string(((insn & 0xf00) >> 0x8)) }
            },
            {
                SHOper(OpType::REG, SHReg(DR0 + ((insn & 0xf00) >> 0x8)), 0, false, false, false, 0, 4)
            },
            false,
            2,
            addr
        );
    }

    if ((insn & 0xf0ff) == 0xf04d) {
        return SHInsn(
            SHOpCode::op_fneg,
            {
                {InstructionToken, "fneg"},
                {TextToken, " "},
                {RegisterToken, "DR" + std::to_string(((insn & 0xf00) >> 0x8)) }
            },
            {
                SHOper(OpType::REG, SHReg(DR0 + ((insn & 0xf00) >> 0x8)), 0, false, false, false, 0, 4)
            },
            false,
            2,
            addr
        );
    }

    if ((insn & 0xf00f) == 0xf000) {
        return SHInsn(
            SHOpCode::op_fadd,
            {
                {InstructionToken, "fadd"},
                {TextToken, " "},
                {RegisterToken, "DR" + std::to_string(((insn & 0xf0) >> 0x4)) },
                {OperandSeparatorToken, ", "},
                {RegisterToken, "DR" + std::to_string(((insn & 0xf00) >> 0x8)) }
            },
            {
                SHOper(OpType::REG, SHReg(DR0 + ((insn & 0xf0) >> 0x4)), 0, false, false, false, 0, 4),
                SHOper(OpType::REG, SHReg(DR0 + ((insn & 0xf00) >> 0x8)), 0, false, false, false, 0, 4)
            },
            false,
            2,
            addr
        );
    }

    if ((insn & 0xf00f) == 0xf001) {
        return SHInsn(
            SHOpCode::op_fsub,
            {
                {InstructionToken, "fsub"},
                {TextToken, " "},
                {RegisterToken, "DR" + std::to_string(((insn & 0xf0) >> 0x4)) },
                {OperandSeparatorToken, ", "},
                {RegisterToken, "DR" + std::to_string(((insn & 0xf00) >> 0x8)) }
            },
            {
                SHOper(OpType::REG, SHReg(DR0 + ((insn & 0xf0) >> 0x4)), 0, false, false, false, 0, 4),
                SHOper(OpType::REG, SHReg(DR0 + ((insn & 0xf00) >> 0x8)), 0, false, false, false, 0, 4)
            },
            false,
            2,
            addr
        );
    }

    if ((insn & 0xf00f) == 0xf002) {
        return SHInsn(
            SHOpCode::op_fmul,
            {
                {InstructionToken, "fmul"},
                {TextToken, " "},
                {RegisterToken, "DR" + std::to_string(((insn & 0xf0) >> 0x4)) },
                {OperandSeparatorToken, ", "},
                {RegisterToken, "DR" + std::to_string(((insn & 0xf00) >> 0x8)) }
            },
            {
                SHOper(OpType::REG, SHReg(DR0 + ((insn & 0xf0) >> 0x4)), 0, false, false, false, 0, 4),
                SHOper(OpType::REG, SHReg(DR0 + ((insn & 0xf00) >> 0x8)), 0, false, false, false, 0, 4)
            },
            false,
            2,
            addr
        );
    }

    if ((insn & 0xf00f) == 0xf003) {
        return SHInsn(
            SHOpCode::op_fdiv,
            {
                {InstructionToken, "fdiv"},
                {TextToken, " "},
                {RegisterToken, "DR" + std::to_string(((insn & 0xf0) >> 0x4)) },
                {OperandSeparatorToken, ", "},
                {RegisterToken, "DR" + std::to_string(((insn & 0xf00) >> 0x8)) }
            },
            {
                SHOper(OpType::REG, SHReg(DR0 + ((insn & 0xf0) >> 0x4)), 0, false, false, false, 0, 4),
                SHOper(OpType::REG, SHReg(DR0 + ((insn & 0xf00) >> 0x8)), 0, false, false, false, 0, 4)
            },
            false,
            2,
            addr
        );
    }

    if ((insn & 0xf0ff) == 0xf06d) {
        return SHInsn(
            SHOpCode::op_fsqrt,
            {
                {InstructionToken, "fsqrt"},
                {TextToken, " "},
                {RegisterToken, "DR" + std::to_string(((insn & 0xf00) >> 0x8)) }
            },
            {
                SHOper(OpType::REG, SHReg(DR0 + ((insn & 0xf00) >> 0x8)), 0, false, false, false, 0, 4)
            },
            false,
            2,
            addr
        );
    }

    if ((insn & 0xf00f) == 0xf004) {
        return SHInsn(
            SHOpCode::op_fcmp_eq,
            {
                {InstructionToken, "fcmp/eq"},
                {TextToken, " "},
                {RegisterToken, "DR" + std::to_string(((insn & 0xf0) >> 0x4)) },
                {OperandSeparatorToken, ", "},
                {RegisterToken, "DR" + std::to_string(((insn & 0xf00) >> 0x8)) }
            },
            {
                SHOper(OpType::REG, SHReg(DR0 + ((insn & 0xf0) >> 0x4)), 0, false, false, false, 0, 4),
                SHOper(OpType::REG, SHReg(DR0 + ((insn & 0xf00) >> 0x8)), 0, false, false, false, 0, 4)
            },
            false,
            2,
            addr
        );
    }

    if ((insn & 0xf00f) == 0xf005) {
        return SHInsn(
            SHOpCode::op_fcmp_gt,
            {
                {InstructionToken, "fcmp/gt"},
                {TextToken, " "},
                {RegisterToken, "DR" + std::to_string(((insn & 0xf0) >> 0x4)) },
                {OperandSeparatorToken, ", "},
                {RegisterToken, "DR" + std::to_string(((insn & 0xf00) >> 0x8)) }
            },
            {
                SHOper(OpType::REG, SHReg(DR0 + ((insn & 0xf0) >> 0x4)), 0, false, false, false, 0, 4),
                SHOper(OpType::REG, SHReg(DR0 + ((insn & 0xf00) >> 0x8)), 0, false, false, false, 0, 4)
            },
            false,
            2,
            addr
        );
    }

    if ((insn & 0xf0ff) == 0xf02d) {
        return SHInsn(
            SHOpCode::op_float,
            {
                {InstructionToken, "float"},
                {TextToken, " "},
                {RegisterToken, "FPUL"},
                {OperandSeparatorToken, ", "},
                {RegisterToken, "DR" + std::to_string(((insn & 0xf00) >> 0x8)) }
            },
            {
                SHOper(OpType::REG, SHReg(FPUL), 0, false, false, false, 0, 4),
                SHOper(OpType::REG, SHReg(DR0 + ((insn & 0xf00) >> 0x8)), 0, false, false, false, 0, 4)
            },
            false,
            2,
            addr
        );
    }

    if ((insn & 0xf0ff) == 0xf03d) {
        return SHInsn(
            SHOpCode::op_ftrc,
            {
                {InstructionToken, "ftrc"},
                {TextToken, " "},
                {RegisterToken, "DR" + std::to_string(((insn & 0xf00) >> 0x8)) },
                {OperandSeparatorToken, ", "},
                {RegisterToken, "FPUL"}
            },
            {
                SHOper(OpType::REG, SHReg(DR0 + ((insn & 0xf00) >> 0x8)), 0, false, false, false, 0, 4),
                SHOper(OpType::REG, SHReg(FPUL), 0, false, false, false, 0, 4)
            },
            false,
            2,
            addr
        );
    }

    if ((insn & 0xf0ff) == 0xf0bd) {
        return SHInsn(
            SHOpCode::op_fcnvds,
            {
                {InstructionToken, "fcnvds"},
                {TextToken, " "},
                {RegisterToken, "DR" + std::to_string(((insn & 0xf00) >> 0x8)) },
                {OperandSeparatorToken, ", "},
                {RegisterToken, "FPUL"}
            },
            {
                SHOper(OpType::REG, SHReg(DR0 + ((insn & 0xf00) >> 0x8)), 0, false, false, false, 0, 4),
                SHOper(OpType::REG, SHReg(FPUL), 0, false, false, false, 0, 4)
            },
            false,
            2,
            addr
        );
    }

    if ((insn & 0xf0ff) == 0xf0ad) {
        return SHInsn(
            SHOpCode::op_fcnvsd,
            {
                {InstructionToken, "fcnvsd"},
                {TextToken, " "},
                {RegisterToken, "FPUL"},
                {OperandSeparatorToken, ", "},
                {RegisterToken, "DR" + std::to_string(((insn & 0xf00) >> 0x8)) }
            },
            {
                SHOper(OpType::REG, SHReg(FPUL), 0, false, false, false, 0, 4),
                SHOper(OpType::REG, SHReg(DR0 + ((insn & 0xf00) >> 0x8)), 0, false, false, false, 0, 4)
            },
            false,
            2,
            addr
        );
    }

    if ((insn & 0xf0ff) == 0x406a) {
        return SHInsn(
            SHOpCode::op_lds,
            {
                {InstructionToken, "lds"},
                {TextToken, " "},
                {RegisterToken, "R" + std::to_string(((insn & 0xf00) >> 0x8)) },
                {OperandSeparatorToken, ", "},
                {RegisterToken, "FPSCR"}
            },
            {
                SHOper(OpType::REG, SHReg(R0 + ((insn & 0xf00) >> 0x8)), 0, false, false, false, 0, 4),
                SHOper(OpType::REG, SHReg(FPSCR), 0, false, false, false, 0, 4)
            },
            false,
            2,
            addr
        );
    }

    if ((insn & 0xf0ff) == 0x006a) {
        return SHInsn(
            SHOpCode::op_sts,
            {
                {InstructionToken, "sts"},
                {TextToken, " "},
                {RegisterToken, "FPSCR"},
                {OperandSeparatorToken, ", "},
                {RegisterToken, "R" + std::to_string(((insn & 0xf00) >> 0x8)) }
            },
            {
                SHOper(OpType::REG, SHReg(FPSCR), 0, false, false, false, 0, 4),
                SHOper(OpType::REG, SHReg(R0 + ((insn & 0xf00) >> 0x8)), 0, false, false, false, 0, 4)
            },
            false,
            2,
            addr
        );
    }

    if ((insn & 0xf0ff) == 0x4066) {
        return SHInsn(
            SHOpCode::op_lds_l,
            {
                {InstructionToken, "lds.l"},
                {TextToken, " "},
                {TextToken, "@"},
                {RegisterToken, "R" + std::to_string(((insn & 0xf00) >> 0x8)) },
                {TextToken, "+"},
                {OperandSeparatorToken, ", "},
                {RegisterToken, "FPSCR"}
            },
            {
                SHOper(OpType::REG, SHReg(R0 + ((insn & 0xf00) >> 0x8)), 0, true, false, false, 4, 4),
                SHOper(OpType::REG, SHReg(FPSCR), 0, false, false, false, 0, 4)
            },
            false,
            2,
            addr
        );
    }

    if ((insn & 0xf0ff) == 0x4062) {
        return SHInsn(
            SHOpCode::op_sts_l,
            {
                {InstructionToken, "sts.l"},
                {TextToken, " "},
                {RegisterToken, "FPSCR"},
                {OperandSeparatorToken, ", "},
                {TextToken, "@-"},
                {RegisterToken, "R" + std::to_string(((insn & 0xf00) >> 0x8)) }
            },
            {
                SHOper(OpType::REG, SHReg(FPSCR), 0, false, false, false, 0, 4),
                SHOper(OpType::REG, SHReg(R0 + ((insn & 0xf00) >> 0x8)), 0, true, false, false, -4, 4)
            },
            false,
            2,
            addr
        );
    }

    if ((insn & 0xf0ff) == 0x405a) {
        return SHInsn(
            SHOpCode::op_lds,
            {
                {InstructionToken, "lds"},
                {TextToken, " "},
                {RegisterToken, "R" + std::to_string(((insn & 0xf00) >> 0x8)) },
                {OperandSeparatorToken, ", "},
                {RegisterToken, "FPUL"}
            },
            {
                SHOper(OpType::REG, SHReg(R0 + ((insn & 0xf00) >> 0x8)), 0, false, false, false, 0, 4),
                SHOper(OpType::REG, SHReg(FPUL), 0, false, false, false, 0, 4)
            },
            false,
            2,
            addr
        );
    }

    if ((insn & 0xf0ff) == 0x005a) {
        return SHInsn(
            SHOpCode::op_sts,
            {
                {InstructionToken, "sts"},
                {TextToken, " "},
                {RegisterToken, "FPUL"},
                {OperandSeparatorToken, ", "},
                {RegisterToken, "R" + std::to_string(((insn & 0xf00) >> 0x8)) }
            },
            {
                SHOper(OpType::REG, SHReg(FPUL), 0, false, false, false, 0, 4),
                SHOper(OpType::REG, SHReg(R0 + ((insn & 0xf00) >> 0x8)), 0, false, false, false, 0, 4)
            },
            false,
            2,
            addr
        );
    }

    if ((insn & 0xf0ff) == 0x4056) {
        return SHInsn(
            SHOpCode::op_lds_l,
            {
                {InstructionToken, "lds.l"},
                {TextToken, " "},
                {TextToken, "@"},
                {RegisterToken, "R" + std::to_string(((insn & 0xf00) >> 0x8)) },
                {TextToken, "+"},
                {OperandSeparatorToken, ", "},
                {RegisterToken, "FPUL"}
            },
            {
                SHOper(OpType::REG, SHReg(R0 + ((insn & 0xf00) >> 0x8)), 0, true, false, false, 4, 4),
                SHOper(OpType::REG, SHReg(FPUL), 0, false, false, false, 0, 4)
            },
            false,
            2,
            addr
        );
    }

    if ((insn & 0xf0ff) == 0x4052) {
        return SHInsn(
            SHOpCode::op_sts_l,
            {
                {InstructionToken, "sts.l"},
                {TextToken, " "},
                {RegisterToken, "FPUL"},
                {OperandSeparatorToken, ", "},
                {TextToken, "@-"},
                {RegisterToken, "R" + std::to_string(((insn & 0xf00) >> 0x8)) }
            },
            {
                SHOper(OpType::REG, SHReg(FPUL), 0, false, false, false, 0, 4),
                SHOper(OpType::REG, SHReg(R0 + ((insn & 0xf00) >> 0x8)), 0, true, false, false, -4, 4)
            },
            false,
            2,
            addr
        );
    }

    if ((insn & 0xffff) == 0xfbfd) {
        return SHInsn(
            SHOpCode::op_frchg,
            {
                {InstructionToken, "frchg"},
                {TextToken, " "}
            },
            {
                
            },
            false,
            2,
            addr
        );
    }

    if ((insn & 0xffff) == 0xf3fd) {
        return SHInsn(
            SHOpCode::op_fschg,
            {
                {InstructionToken, "fschg"},
                {TextToken, " "}
            },
            {
                
            },
            false,
            2,
            addr
        );
    }

    if ((insn & 0xffff) == 0xf7fd) {
        return SHInsn(
            SHOpCode::op_fpchg,
            {
                {InstructionToken, "fpchg"},
                {TextToken, " "}
            },
            {
                
            },
            false,
            2,
            addr
        );
    }

    if ((insn & 0xffff) == 0xf000) {
        return SHInsn(
            SHOpCode::op_nopx,
            {
                {InstructionToken, "nopx"},
                {TextToken, " "}
            },
            {
                
            },
            false,
            2,
            addr
        );
    }

    if ((insn & 0xff0f) == 0xf004) {
        return SHInsn(
            SHOpCode::op_movx_w,
            {
                {InstructionToken, "movx.w"},
                {TextToken, " "},
                {TextToken, "@"},
                {TextToken, "0"},
                {OperandSeparatorToken, ", "},
                {TextToken, "0"}
            },
            {
                SHOper(OpType::UNKNOWN, SHReg::InvalidReg, 0, true, false, false, 0, 0),
                SHOper(OpType::UNKNOWN, SHReg::InvalidReg, 0, false, false, false, 0, 0)
            },
            false,
            2,
            addr
        );
    }

    if ((insn & 0xff0f) == 0xf008) {
        return SHInsn(
            SHOpCode::op_movx_w,
            {
                {InstructionToken, "movx.w"},
                {TextToken, " "},
                {TextToken, "@"},
                {TextToken, "0"},
                {TextToken, "+"},
                {OperandSeparatorToken, ", "},
                {TextToken, "0"}
            },
            {
                SHOper(OpType::UNKNOWN, SHReg::InvalidReg, 0, true, false, false, 2, 0),
                SHOper(OpType::UNKNOWN, SHReg::InvalidReg, 0, false, false, false, 0, 0)
            },
            false,
            2,
            addr
        );
    }

    if ((insn & 0xff0f) == 0xf00c) {
        return SHInsn(
            SHOpCode::op_movx_w,
            {
                {InstructionToken, "movx.w"},
                {TextToken, " "},
                {TextToken, "@"},
                {TextToken, "0"},
                {OperandSeparatorToken, ", "},
                {TextToken, "0"}
            },
            {
                SHOper(OpType::UNKNOWN, SHReg::InvalidReg, 0, true, false, false, 0, 0),
                SHOper(OpType::UNKNOWN, SHReg::InvalidReg, 0, false, false, false, 0, 0)
            },
            false,
            2,
            addr
        );
    }

    if ((insn & 0xff0f) == 0xf004) {
        return SHInsn(
            SHOpCode::op_movx_w,
            {
                {InstructionToken, "movx.w"},
                {TextToken, " "},
                {TextToken, "0"},
                {OperandSeparatorToken, ", "},
                {TextToken, "@"},
                {TextToken, "0"}
            },
            {
                SHOper(OpType::UNKNOWN, SHReg::InvalidReg, 0, false, false, false, 0, 0),
                SHOper(OpType::UNKNOWN, SHReg::InvalidReg, 0, true, false, false, 0, 0)
            },
            false,
            2,
            addr
        );
    }

    if ((insn & 0xff0f) == 0xf008) {
        return SHInsn(
            SHOpCode::op_movx_w,
            {
                {InstructionToken, "movx.w"},
                {TextToken, " "},
                {TextToken, "0"},
                {OperandSeparatorToken, ", "},
                {TextToken, "@"},
                {TextToken, "0"},
                {TextToken, "+"}
            },
            {
                SHOper(OpType::UNKNOWN, SHReg::InvalidReg, 0, false, false, false, 0, 0),
                SHOper(OpType::UNKNOWN, SHReg::InvalidReg, 0, true, false, false, 2, 0)
            },
            false,
            2,
            addr
        );
    }

    if ((insn & 0xff0f) == 0xf00c) {
        return SHInsn(
            SHOpCode::op_movx_w,
            {
                {InstructionToken, "movx.w"},
                {TextToken, " "},
                {TextToken, "0"},
                {OperandSeparatorToken, ", "},
                {TextToken, "@"},
                {TextToken, "0"}
            },
            {
                SHOper(OpType::UNKNOWN, SHReg::InvalidReg, 0, false, false, false, 0, 0),
                SHOper(OpType::UNKNOWN, SHReg::InvalidReg, 0, true, false, false, 0, 0)
            },
            false,
            2,
            addr
        );
    }

    if ((insn & 0xff00) == 0xf000) {
        return SHInsn(
            SHOpCode::op_nopy,
            {
                {InstructionToken, "nopy"},
                {TextToken, " "}
            },
            {
                
            },
            false,
            2,
            addr
        );
    }

    if ((insn & 0xff00) == 0xf000) {
        return SHInsn(
            SHOpCode::op_movy_w,
            {
                {InstructionToken, "movy.w"},
                {TextToken, " "},
                {TextToken, "@"},
                {TextToken, "0"},
                {OperandSeparatorToken, ", "},
                {TextToken, "0"}
            },
            {
                SHOper(OpType::UNKNOWN, SHReg::InvalidReg, 0, true, false, false, 0, 0),
                SHOper(OpType::UNKNOWN, SHReg::InvalidReg, 0, false, false, false, 0, 0)
            },
            false,
            2,
            addr
        );
    }

    if ((insn & 0xff00) == 0xf000) {
        return SHInsn(
            SHOpCode::op_movy_w,
            {
                {InstructionToken, "movy.w"},
                {TextToken, " "},
                {TextToken, "@"},
                {TextToken, "0"},
                {TextToken, "+"},
                {OperandSeparatorToken, ", "},
                {TextToken, "0"}
            },
            {
                SHOper(OpType::UNKNOWN, SHReg::InvalidReg, 0, true, false, false, 2, 0),
                SHOper(OpType::UNKNOWN, SHReg::InvalidReg, 0, false, false, false, 0, 0)
            },
            false,
            2,
            addr
        );
    }

    if ((insn & 0xff00) == 0xf000) {
        return SHInsn(
            SHOpCode::op_movy_w,
            {
                {InstructionToken, "movy.w"},
                {TextToken, " "},
                {TextToken, "@"},
                {TextToken, "0"},
                {OperandSeparatorToken, ", "},
                {TextToken, "0"}
            },
            {
                SHOper(OpType::UNKNOWN, SHReg::InvalidReg, 0, true, false, false, 0, 0),
                SHOper(OpType::UNKNOWN, SHReg::InvalidReg, 0, false, false, false, 0, 0)
            },
            false,
            2,
            addr
        );
    }

    if ((insn & 0xff00) == 0xf000) {
        return SHInsn(
            SHOpCode::op_movy_w,
            {
                {InstructionToken, "movy.w"},
                {TextToken, " "},
                {TextToken, "0"},
                {OperandSeparatorToken, ", "},
                {TextToken, "@"},
                {TextToken, "0"}
            },
            {
                SHOper(OpType::UNKNOWN, SHReg::InvalidReg, 0, false, false, false, 0, 0),
                SHOper(OpType::UNKNOWN, SHReg::InvalidReg, 0, true, false, false, 0, 0)
            },
            false,
            2,
            addr
        );
    }

    if ((insn & 0xff00) == 0xf000) {
        return SHInsn(
            SHOpCode::op_movy_w,
            {
                {InstructionToken, "movy.w"},
                {TextToken, " "},
                {TextToken, "0"},
                {OperandSeparatorToken, ", "},
                {TextToken, "@"},
                {TextToken, "0"},
                {TextToken, "+"}
            },
            {
                SHOper(OpType::UNKNOWN, SHReg::InvalidReg, 0, false, false, false, 0, 0),
                SHOper(OpType::UNKNOWN, SHReg::InvalidReg, 0, true, false, false, 2, 0)
            },
            false,
            2,
            addr
        );
    }

    if ((insn & 0xff00) == 0xf000) {
        return SHInsn(
            SHOpCode::op_movy_w,
            {
                {InstructionToken, "movy.w"},
                {TextToken, " "},
                {TextToken, "0"},
                {OperandSeparatorToken, ", "},
                {TextToken, "@"},
                {TextToken, "0"}
            },
            {
                SHOper(OpType::UNKNOWN, SHReg::InvalidReg, 0, false, false, false, 0, 0),
                SHOper(OpType::UNKNOWN, SHReg::InvalidReg, 0, true, false, false, 0, 0)
            },
            false,
            2,
            addr
        );
    }

    if ((insn & 0xff0f) == 0xf400) {
        return SHInsn(
            SHOpCode::op_movs_w,
            {
                {InstructionToken, "movs.w"},
                {TextToken, " "},
                {TextToken, "@-"},
                {TextToken, "0"},
                {OperandSeparatorToken, ", "},
                {TextToken, "0"}
            },
            {
                SHOper(OpType::UNKNOWN, SHReg::InvalidReg, 0, true, false, false, -2, 0),
                SHOper(OpType::UNKNOWN, SHReg::InvalidReg, 0, false, false, false, 0, 0)
            },
            false,
            2,
            addr
        );
    }

    if ((insn & 0xff0f) == 0xf404) {
        return SHInsn(
            SHOpCode::op_movs_w,
            {
                {InstructionToken, "movs.w"},
                {TextToken, " "},
                {TextToken, "@"},
                {TextToken, "0"},
                {OperandSeparatorToken, ", "},
                {TextToken, "0"}
            },
            {
                SHOper(OpType::UNKNOWN, SHReg::InvalidReg, 0, true, false, false, 0, 0),
                SHOper(OpType::UNKNOWN, SHReg::InvalidReg, 0, false, false, false, 0, 0)
            },
            false,
            2,
            addr
        );
    }

    if ((insn & 0xff0f) == 0xf408) {
        return SHInsn(
            SHOpCode::op_movs_w,
            {
                {InstructionToken, "movs.w"},
                {TextToken, " "},
                {TextToken, "@"},
                {TextToken, "0"},
                {TextToken, "+"},
                {OperandSeparatorToken, ", "},
                {TextToken, "0"}
            },
            {
                SHOper(OpType::UNKNOWN, SHReg::InvalidReg, 0, true, false, false, 2, 0),
                SHOper(OpType::UNKNOWN, SHReg::InvalidReg, 0, false, false, false, 0, 0)
            },
            false,
            2,
            addr
        );
    }

    if ((insn & 0xff0f) == 0xf40c) {
        return SHInsn(
            SHOpCode::op_movs_w,
            {
                {InstructionToken, "movs.w"},
                {TextToken, " "},
                {TextToken, "@"},
                {TextToken, "0"},
                {OperandSeparatorToken, ", "},
                {TextToken, "0"}
            },
            {
                SHOper(OpType::UNKNOWN, SHReg::InvalidReg, 0, true, false, false, 0, 0),
                SHOper(OpType::UNKNOWN, SHReg::InvalidReg, 0, false, false, false, 0, 0)
            },
            false,
            2,
            addr
        );
    }

    if ((insn & 0xff0f) == 0xf401) {
        return SHInsn(
            SHOpCode::op_movs_w,
            {
                {InstructionToken, "movs.w"},
                {TextToken, " "},
                {TextToken, "0"},
                {OperandSeparatorToken, ", "},
                {TextToken, "@-"},
                {TextToken, "0"}
            },
            {
                SHOper(OpType::UNKNOWN, SHReg::InvalidReg, 0, false, false, false, 0, 0),
                SHOper(OpType::UNKNOWN, SHReg::InvalidReg, 0, true, false, false, -2, 0)
            },
            false,
            2,
            addr
        );
    }

    if ((insn & 0xff0f) == 0xf405) {
        return SHInsn(
            SHOpCode::op_movs_w,
            {
                {InstructionToken, "movs.w"},
                {TextToken, " "},
                {TextToken, "0"},
                {OperandSeparatorToken, ", "},
                {TextToken, "@"},
                {TextToken, "0"}
            },
            {
                SHOper(OpType::UNKNOWN, SHReg::InvalidReg, 0, false, false, false, 0, 0),
                SHOper(OpType::UNKNOWN, SHReg::InvalidReg, 0, true, false, false, 0, 0)
            },
            false,
            2,
            addr
        );
    }

    if ((insn & 0xff0f) == 0xf409) {
        return SHInsn(
            SHOpCode::op_movs_w,
            {
                {InstructionToken, "movs.w"},
                {TextToken, " "},
                {TextToken, "0"},
                {OperandSeparatorToken, ", "},
                {TextToken, "@"},
                {TextToken, "0"},
                {TextToken, "+"}
            },
            {
                SHOper(OpType::UNKNOWN, SHReg::InvalidReg, 0, false, false, false, 0, 0),
                SHOper(OpType::UNKNOWN, SHReg::InvalidReg, 0, true, false, false, 2, 0)
            },
            false,
            2,
            addr
        );
    }

    if ((insn & 0xff0f) == 0xf40d) {
        return SHInsn(
            SHOpCode::op_movs_w,
            {
                {InstructionToken, "movs.w"},
                {TextToken, " "},
                {TextToken, "0"},
                {OperandSeparatorToken, ", "},
                {TextToken, "@"},
                {TextToken, "0"}
            },
            {
                SHOper(OpType::UNKNOWN, SHReg::InvalidReg, 0, false, false, false, 0, 0),
                SHOper(OpType::UNKNOWN, SHReg::InvalidReg, 0, true, false, false, 0, 0)
            },
            false,
            2,
            addr
        );
    }

    if ((insn & 0xff0f) == 0xf402) {
        return SHInsn(
            SHOpCode::op_movs_l,
            {
                {InstructionToken, "movs.l"},
                {TextToken, " "},
                {TextToken, "@-"},
                {TextToken, "0"},
                {OperandSeparatorToken, ", "},
                {TextToken, "0"}
            },
            {
                SHOper(OpType::UNKNOWN, SHReg::InvalidReg, 0, true, false, false, -4, 0),
                SHOper(OpType::UNKNOWN, SHReg::InvalidReg, 0, false, false, false, 0, 0)
            },
            false,
            2,
            addr
        );
    }

    if ((insn & 0xff0f) == 0xf406) {
        return SHInsn(
            SHOpCode::op_movs_l,
            {
                {InstructionToken, "movs.l"},
                {TextToken, " "},
                {TextToken, "@"},
                {TextToken, "0"},
                {OperandSeparatorToken, ", "},
                {TextToken, "0"}
            },
            {
                SHOper(OpType::UNKNOWN, SHReg::InvalidReg, 0, true, false, false, 0, 0),
                SHOper(OpType::UNKNOWN, SHReg::InvalidReg, 0, false, false, false, 0, 0)
            },
            false,
            2,
            addr
        );
    }

    if ((insn & 0xff0f) == 0xf40a) {
        return SHInsn(
            SHOpCode::op_movs_l,
            {
                {InstructionToken, "movs.l"},
                {TextToken, " "},
                {TextToken, "@"},
                {TextToken, "0"},
                {TextToken, "+"},
                {OperandSeparatorToken, ", "},
                {TextToken, "0"}
            },
            {
                SHOper(OpType::UNKNOWN, SHReg::InvalidReg, 0, true, false, false, 4, 0),
                SHOper(OpType::UNKNOWN, SHReg::InvalidReg, 0, false, false, false, 0, 0)
            },
            false,
            2,
            addr
        );
    }

    if ((insn & 0xff0f) == 0xf40e) {
        return SHInsn(
            SHOpCode::op_movs_l,
            {
                {InstructionToken, "movs.l"},
                {TextToken, " "},
                {TextToken, "@"},
                {TextToken, "0"},
                {OperandSeparatorToken, ", "},
                {TextToken, "0"}
            },
            {
                SHOper(OpType::UNKNOWN, SHReg::InvalidReg, 0, true, false, false, 0, 0),
                SHOper(OpType::UNKNOWN, SHReg::InvalidReg, 0, false, false, false, 0, 0)
            },
            false,
            2,
            addr
        );
    }

    if ((insn & 0xff0f) == 0xf403) {
        return SHInsn(
            SHOpCode::op_movs_l,
            {
                {InstructionToken, "movs.l"},
                {TextToken, " "},
                {TextToken, "0"},
                {OperandSeparatorToken, ", "},
                {TextToken, "@-"},
                {TextToken, "0"}
            },
            {
                SHOper(OpType::UNKNOWN, SHReg::InvalidReg, 0, false, false, false, 0, 0),
                SHOper(OpType::UNKNOWN, SHReg::InvalidReg, 0, true, false, false, -4, 0)
            },
            false,
            2,
            addr
        );
    }

    if ((insn & 0xff0f) == 0xf407) {
        return SHInsn(
            SHOpCode::op_movs_l,
            {
                {InstructionToken, "movs.l"},
                {TextToken, " "},
                {TextToken, "0"},
                {OperandSeparatorToken, ", "},
                {TextToken, "@"},
                {TextToken, "0"}
            },
            {
                SHOper(OpType::UNKNOWN, SHReg::InvalidReg, 0, false, false, false, 0, 0),
                SHOper(OpType::UNKNOWN, SHReg::InvalidReg, 0, true, false, false, 0, 0)
            },
            false,
            2,
            addr
        );
    }

    if ((insn & 0xff0f) == 0xf40b) {
        return SHInsn(
            SHOpCode::op_movs_l,
            {
                {InstructionToken, "movs.l"},
                {TextToken, " "},
                {TextToken, "0"},
                {OperandSeparatorToken, ", "},
                {TextToken, "@"},
                {TextToken, "0"},
                {TextToken, "+"}
            },
            {
                SHOper(OpType::UNKNOWN, SHReg::InvalidReg, 0, false, false, false, 0, 0),
                SHOper(OpType::UNKNOWN, SHReg::InvalidReg, 0, true, false, false, 4, 0)
            },
            false,
            2,
            addr
        );
    }

    if ((insn & 0xff0f) == 0xf40f) {
        return SHInsn(
            SHOpCode::op_movs_l,
            {
                {InstructionToken, "movs.l"},
                {TextToken, " "},
                {TextToken, "0"},
                {OperandSeparatorToken, ", "},
                {TextToken, "@"},
                {TextToken, "0"}
            },
            {
                SHOper(OpType::UNKNOWN, SHReg::InvalidReg, 0, false, false, false, 0, 0),
                SHOper(OpType::UNKNOWN, SHReg::InvalidReg, 0, true, false, false, 0, 0)
            },
            false,
            2,
            addr
        );
    }

   return {};

}
