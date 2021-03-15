#include "disasm.h"
#include "binaryninjaapi.h"
#include "il.h"

using namespace BinaryNinja;

ExprId create_op(LowLevelILFunction &il, SHInsn &insn, uint8_t op_idx, bool sign_extend = false, uint8_t disp_shift = 0, uint8_t width = 4) {
    if (op_idx >= insn.operands.size()) {
        LogError("Invalid insn: 0x%x", insn.addr);
        return 0;
    }

    auto op = insn.operands[op_idx];
    switch (op.type) {

    case OpType::REG:
        if (op.is_pair) {
            auto op2 = insn.operands[op_idx + 1];
            return il.Add(
                4,
                il.Register(op.op_size, op.reg),
                il.Register(op2.op_size, op2.reg)
            );
        } else {
            if (op.reg == SHReg::PC) {
                return il.Const(4, insn.addr);
            } else {
                return il.Register(op.op_size, op.reg);
            }
        }

    case OpType::DISP:
        if (op.is_label) {
            return il.ConstPointer(4, op.imm);
        }
        if (op.is_pair) {
            if ((op_idx + 1) >= insn.operands.size()) {
                LogError("Invalid insn: 0x%x", insn.addr);
                return 0;
            }

            auto next_op = create_op(il, insn, op_idx + 1);
            bool next_op_pc = false;
            if (insn.operands[op_idx + 1].reg == SHReg::PC) {
                next_op = il.And(
                    4,
                    next_op,
                    il.Const(4, 0xFFFFFFFC)
                );
                next_op_pc = true;
            }
            next_op = il.Add(
                4,
                il.ShiftLeft(
                    4,
                    il.Const(4, op.imm),
                    il.Const(4, disp_shift)
                ),
                next_op
            );
            if (next_op_pc) {
                next_op = il.Add(
                    4,
                    next_op,
                    il.Const(4, 4)
                );
            }
            return next_op;
        }
        else {
            return il.Const(op.op_size, op.imm);
        }
    case OpType::IMM: {
        auto ret_val = il.Const(op.op_size, op.imm);
        if (sign_extend) {
            ret_val = il.SignExtend(4, ret_val);
        } else {
            ret_val = il.ZeroExtend(4, ret_val);
        }
        return ret_val;
    }
    default:
        LogError("Invalid oper type at: 0x%x", insn.addr);
        return 0;
    }
}

SHReg get_reg(SHInsn &insn, uint8_t op_idx) {
    if (op_idx >= insn.operands.size() ||
        insn.operands[op_idx].type != OpType::REG) {
        LogError("Invalid insn: 0x%x", insn.addr);
        return SHReg::InvalidReg;
    }
    return insn.operands[op_idx].reg;
}

void lift_mov(LowLevelILFunction &il, SHInsn &insn, bool sign_extend, uint8_t disp_shift, uint8_t width) {
    if (insn.operands.size() < 2) {
        LogError("Invalid insn: 0x%x", insn.addr);
        return;
    }

    auto first_op = insn.operands[0];
    auto second_op = insn.operands[1];

    if (first_op.is_ref) {
        auto val_expr = create_op(il, insn, 0, false, disp_shift, width);
        val_expr = il.Load(width, val_expr);

        if (sign_extend) {
            val_expr = il.SignExtend(4, val_expr);
        }

        auto last_op = insn.operands[insn.operands.size() - 1];

        il.AddInstruction(
            il.SetRegister(
                4,
                last_op.reg,
                val_expr
            )
        );

        if (first_op.mod_reg) {
            il.AddInstruction(
                il.SetRegister(
                    4,
                    second_op.reg,
                    il.Add(
                        4,
                        il.Register(second_op.op_size, second_op.reg),
                        il.Const(4, second_op.mod_reg)
                    )
                )
            );
        }
    }
    else if (second_op.is_ref) {
        il.AddInstruction(
            il.Store(
                width,
                create_op(il, insn, 1, false, disp_shift, width),
                create_op(il, insn, 0)
            )
        );

        if (second_op.mod_reg && second_op.type == OpType::REG) {
            il.AddInstruction(
                il.SetRegister(
                    4,
                    second_op.reg,
                    il.Add(
                        4,
                        il.Register(second_op.op_size, second_op.reg),
                        il.Const(4, second_op.mod_reg)
                    )
                )
            );
        }
    }
    else if (first_op.type == OpType::REG && second_op.type == OpType::REG) {
        il.AddInstruction(
            il.SetRegister(
                4,
                second_op.reg,
                il.Register(4, first_op.reg)
            )
        );
    }
    else {
        LogInfo("Unknown mov insn at: 0x%x", insn.addr);
        il.AddInstruction(il.Unimplemented());
    }
}

void lift(Architecture* arch, SHInsn &insn, LowLevelILFunction &il) {
    switch (insn.opcode) {

    // mov's
    case SHOpCode::op_mov:
    case SHOpCode::op_movi20:
        il.AddInstruction(
            il.SetRegister(
                4,
                get_reg(insn, 1),
                create_op(il, insn, 0, true)
            )
        );
        break;
    case SHOpCode::op_movi20s:
        il.AddInstruction(
            il.SetRegister(
                4,
                get_reg(insn, 1),
                il.SignExtend(
                    4,
                    il.ShiftLeft(
                        4,
                        il.Const(insn.operands[0].op_size, insn.operands[0].imm),
                        il.Const(4, 8)
                    )
                )
            )
        );
        break;

    case SHOpCode::op_mova: {
        auto val_expr = create_op(il, insn, 0, false, 2, 4);

        il.AddInstruction(
            il.SetRegister(
                4,
                SHReg::R0,
                val_expr
            )
        );
        break;
    }
    case SHOpCode::op_mov_l: {
        bool sign_extend = false;
        if (insn.opcode == SHOpCode::op_mov_l &&
            insn.operands[0].is_pair &&
            insn.operands[0].is_ref && insn.operands[1].reg == SHReg::PC) {
                sign_extend = true;
            }
        lift_mov(il, insn, sign_extend, 2, 4);
        break;
    }

    case SHOpCode::op_mov_w:
        lift_mov(il, insn, true, 1, 2);
        break;

    case SHOpCode::op_mov_b:
        lift_mov(il, insn, true, 0, 1);
        break;

    case SHOpCode::op_movt:
        if (insn.operands.empty() ||
            insn.operands[0].type != OpType::REG) {
            LogInfo("Invalid instruction: 0x%x", insn.addr);
            break;
        }
        il.AddInstruction(
            il.SetRegister(
                4,
                insn.operands[0].reg,
                il.Flag(SHFlags::T_FLAG)
            )
        );
        break;
    case SHOpCode::op_movrt:
        if (insn.operands.empty() ||
            insn.operands[0].type != OpType::REG) {
            LogInfo("Invalid instruction: 0x%x", insn.addr);
            break;
        }
        il.AddInstruction(
            il.SetRegister(
                4,
                insn.operands[0].reg,
                il.Not(1,
                    il.Flag(SHFlags::T_FLAG)
                )
            )
        );
        break;

    case SHOpCode::op_movu_b:
        il.AddInstruction(
            il.SetRegister(
                4,
                get_reg(insn, 1),
                il.ZeroExtend(
                    4,
                    il.Load(
                        1,
                        create_op(il, insn, 0, false, 0, 1)
                    )
                )
            )
        );
        break;
    case SHOpCode::op_movu_w:
        il.AddInstruction(
            il.SetRegister(
                4,
                get_reg(insn, 1),
                il.ZeroExtend(
                    4,
                    il.Load(
                        2,
                        create_op(il, insn, 1, false, 0, 1)
                    )
                )
            )
        );
        break;
    case SHOpCode::op_movco_l: {
        il.AddInstruction(
            il.SetFlag(
                SHFlags::LDST,
                il.Flag(SHFlags::T_FLAG)
            )
        );

        LowLevelILLabel trueLabel, falseLabel;
        il.AddInstruction(
            il.If(
                il.Flag(SHFlags::T_FLAG),
                trueLabel,
                falseLabel
            )
        );
        il.MarkLabel(trueLabel);

        il.AddInstruction(
            il.Store(
                4,
                create_op(il, insn, 0),
                create_op(il, insn, 1)
            )
        );

        il.MarkLabel(falseLabel);

        il.AddInstruction(
            il.SetFlag(
                SHFlags::LDST,
                il.Const(1, 0)
            )
        );

        break;
    }

    case SHOpCode::op_nott:
        il.AddInstruction(
            il.SetFlag(
                SHFlags::T_FLAG,
                il.Not(
                    1,
                    il.Flag(SHFlags::T_FLAG)
                )
            )
        );
        break;
    // Logical

    case SHOpCode::op_and:
        il.AddInstruction(
            il.SetRegister(
                4,
                get_reg(insn, 1),
                il.And(
                    4,
                    create_op(il, insn, 1),
                    create_op(il, insn, 0)
                )
            )
        );
        break;

    case SHOpCode::op_and_b:
        il.AddInstruction(
            il.Store(
                1,
                il.Add(
                    4,
                    il.Register(4, SHReg::GBR),
                    il.Register(4, SHReg::R0)
                ),
                il.And(
                    4,
                    il.Add(
                        4,
                        il.Register(4, SHReg::GBR),
                        il.Register(4, SHReg::R0)
                    ),
                    il.ZeroExtend(
                        4,
                        create_op(il, insn, 0)
                    )
                )
            )
        );
        break;

    case SHOpCode::op_not:
        il.AddInstruction(
            il.SetRegister(
                4,
                get_reg(insn, 1),
                il.Not(
                    4,
                    create_op(il, insn, 0)
                )
            )
        );
        break;

    case SHOpCode::op_or:
        il.AddInstruction(
            il.SetRegister(
                4,
                get_reg(insn, 1),
                il.Or(
                    4,
                    create_op(il, insn, 1),
                    create_op(il, insn, 0)
                )
            )
        );
        break;
    case SHOpCode::op_or_b:
        il.AddInstruction(
            il.Store(
                1,
                il.Add(
                    4,
                    il.Register(4, SHReg::GBR),
                    il.Register(4, SHReg::R0)
                ),
                il.Or(
                    4,
                    il.Add(
                        4,
                        il.Register(4, SHReg::GBR),
                        il.Register(4, SHReg::R0)
                    ),
                    il.ZeroExtend(
                        4,
                        create_op(il, insn, 0)
                    )
                )
            )
        );
        break;

    case SHOpCode::op_tas_b: {
        LowLevelILLabel trueLabel, falseLabel;

        auto tmp_load = il.Load(1, create_op(il, insn, 0));

        auto cond = il.Not(1, tmp_load);

        il.AddInstruction(
            il.If(
                cond,
                trueLabel,
                falseLabel
            )
        );

        il.MarkLabel(trueLabel);
        il.AddInstruction(
            il.SetFlag(SHFlags::T_FLAG, il.Const(1, 1))
        );
        il.MarkLabel(falseLabel);


        il.AddInstruction(
            il.Store(
                1,
                create_op(il, insn, 0),
                il.And(
                    4,
                    tmp_load,
                    il.Const(4, 0x00000080)
                )
            )
        );

        break;
    }

    case SHOpCode::op_tst: {
        il.AddInstruction(
            il.And(
                4,
                create_op(il, insn, 1),
                create_op(il, insn, 0),
                SHFlagGroups::IL_FLAGWRITE_ALL
            )
        );

        break;
    }

    case SHOpCode::op_xor:
        il.AddInstruction(
            il.SetRegister(
                4,
                get_reg(insn, 1),
                il.Xor(
                    4,
                    create_op(il, insn, 1),
                    create_op(il, insn, 0)
                )
            )
        );
        break;

    case SHOpCode::op_cmp_eq:
        il.AddInstruction(
            il.SetFlag(SHFlags::T_FLAG,
                il.CompareEqual(4,
                    create_op(il, insn, 0, true),
                    create_op(il, insn, 1)
                )
            )
        );
        break;

    case SHOpCode::op_cmp_hs:
        il.AddInstruction(
            il.SetFlag(SHFlags::T_FLAG,
                il.CompareUnsignedGreaterEqual(4,
                    create_op(il, insn, 1, true),
                    create_op(il, insn, 0)
                )
            )
        );
        break;
    case SHOpCode::op_cmp_ge:
        il.AddInstruction(
            il.SetFlag(SHFlags::T_FLAG,
                il.CompareSignedGreaterEqual(4,
                    create_op(il, insn, 1, true),
                    create_op(il, insn, 0)
                )
            )
        );
        break;
    case SHOpCode::op_cmp_hi:
        il.AddInstruction(
            il.SetFlag(SHFlags::T_FLAG,
                il.CompareUnsignedGreaterThan(4,
                    create_op(il, insn, 1, true),
                    create_op(il, insn, 0)
                )
            )
        );
        break;
    case SHOpCode::op_cmp_gt:
        il.AddInstruction(
            il.SetFlag(SHFlags::T_FLAG,
                il.CompareSignedGreaterThan(4,
                    create_op(il, insn, 1, true),
                    create_op(il, insn, 0)
                )
            )
        );
        break;
    case SHOpCode::op_cmp_pl:
        il.AddInstruction(
            il.SetFlag(SHFlags::T_FLAG,
                il.CompareSignedGreaterThan(4,
                    create_op(il, insn, 0),
                    il.Const(4, 0)
                )
            )
        );
        break;
    case SHOpCode::op_cmp_pz:
        il.AddInstruction(
            il.SetFlag(SHFlags::T_FLAG,
                il.CompareSignedGreaterEqual(4,
                    create_op(il, insn, 0),
                    il.Const(4, 0)
                )
            )
        );
        break;

    case SHOpCode::op_cmp_str: {
        auto tmp = LLIL_TEMP(10);
        auto HH = LLIL_TEMP(11);
        auto HL = LLIL_TEMP(12);
        auto LH = LLIL_TEMP(13);
        auto LL = LLIL_TEMP(14);

        // temp = R[n] ^ R[m];
        // HH = (temp & 0xFF000000) >> 24;
        // HL = (temp & 0x00FF0000) >> 16;
        // LH = (temp & 0x0000FF00) >> 8;
        // LL = temp & 0x000000FF;
        // HH = HH && HL && LH && LL;

        il.AddInstruction(
            il.SetRegister(
                4,
                tmp,
                il.Xor(
                    4,
                    create_op(il, insn, 1),
                    create_op(il, insn, 0)
                )
            )
        );

        il.AddInstruction(
            il.SetRegister(
                4,
                HH,
                il.LogicalShiftRight(
                    4,
                    il.And(
                        4,
                        il.Register(4, tmp),
                        il.Const(4, 0xFF000000)
                    ),
                    il.Const(4, 24)
                )
            )
        );
        il.AddInstruction(
            il.SetRegister(
                4,
                HL,
                il.LogicalShiftRight(
                    4,
                    il.And(
                        4,
                        il.Register(4, tmp),
                        il.Const(4, 0x00FF0000)
                    ),
                    il.Const(4, 16)
                )
            )
        );
        il.AddInstruction(
            il.SetRegister(
                4,
                LH,
                il.LogicalShiftRight(
                    4,
                    il.And(
                        4,
                        il.Register(4, tmp),
                        il.Const(4, 0x0000FF00)
                    ),
                    il.Const(4, 8)
                )
            )
        );

        il.AddInstruction(
            il.SetRegister(
                4,
                LL,
                il.And(
                    4,
                    il.Register(4, tmp),
                    il.Const(4, 0x000000FF)
                )
            )
        );

        il.AddInstruction(
            il.SetRegister(4,
                HH,
                il.And(4,
                    il.Register(4, HH),
                    il.And(4,
                        il.Register(4, HL),
                        il.And(4,
                            il.Register(4, LH),
                            il.Register(4, LL)
                        )
                    )
                )
            )
        );

        il.AddInstruction(
            il.SetFlag(SHFlags::T_FLAG,
                il.CompareEqual(4,
                    il.Register(4, HH),
                    il.Const(4, 0)
                )
            )
        );
        break;
    }

    case SHOpCode::op_dt:
        il.AddInstruction(
            il.SetRegister(
                4,
                insn.operands[0].reg,
                il.Sub(
                    4,
                    il.Register(4, insn.operands[0].reg),
                    il.Const(4, 1),
                    SHFlagGroups::IL_FLAGWRITE_ALL
                )
            )
        );
        break;

    case SHOpCode::op_exts_b:
    case SHOpCode::op_exts_w: {
        uint8_t width = 1;
        if (insn.opcode == SHOpCode::op_exts_w) {
            width = 2;
        }
        il.AddInstruction(
            il.SetRegister(
                4,
                get_reg(insn, 1),
                il.SignExtend(
                    width,
                    create_op(il, insn, 0)
                )
            )
        );
        break;
    }
    case SHOpCode::op_extu_b:
    case SHOpCode::op_extu_w: {
        uint8_t width = 1;
        if (insn.opcode == SHOpCode::op_extu_w) {
            width = 2;
        }
        il.AddInstruction(
            il.SetRegister(
                4,
                get_reg(insn, 1),
                il.ZeroExtend(
                    width,
                    create_op(il, insn, 0)
                )
            )
        );
        break;
    }

    case SHOpCode::op_mul_l:
        il.AddInstruction(
            il.SetRegister(
                4,
                SHReg::MACL,
                il.Mult(
                    4,
                    create_op(il, insn, 1),
                    create_op(il, insn, 0)
                )
            )
        );
        break;
    case SHOpCode::op_mulr:
        il.AddInstruction(
            il.SetRegister(
                4,
                get_reg(insn, 1),
                il.Mult(
                    4,
                    create_op(il, insn, 0),
                    create_op(il, insn, 1)
                )
            )
        );
        break;

    case SHOpCode::op_neg:
        il.AddInstruction(
            il.SetRegister(
                4,
                get_reg(insn, 1),
                il.Sub(
                    4,
                    il.Const(4, 0),
                    il.Register(insn.operands[0].op_size, insn.operands[0].reg)
                )
            )
        );
        break;
    case SHOpCode::op_negc: {
        auto tmp_reg = LLIL_TEMP(0);

        il.AddInstruction(
            il.SetRegister(
                4,
                tmp_reg,
                il.Sub(
                    4,
                    il.Const(4, 0),
                    il.Register(insn.operands[0].op_size, insn.operands[0].reg)
                )
            )
        );

        il.AddInstruction(
            il.SetRegister(
                4,
                get_reg(insn, 1),
                il.Sub(
                    4,
                    il.Register(4, tmp_reg),
                    il.Flag(SHFlags::T_FLAG)
                )
            )
        );

        il.AddInstruction(
            il.SetFlag(
                SHFlags::T_FLAG,
                il.CompareUnsignedLessEqual(
                    4,
                    il.Const(4, 0),
                    il.Register(4, tmp_reg)
                )
            )
        );

        // TODO: There must be a way to do this with built-in flags
        LowLevelILLabel trueLabel, falseLabel;
        il.AddInstruction(
            il.If(
                il.CompareUnsignedLessThan(
                    4,
                    il.Register(4, tmp_reg),
                    il.Register(insn.operands[0].op_size, insn.operands[0].reg)
                ),
                trueLabel,
                falseLabel
            )
        );
        il.MarkLabel(trueLabel);
        il.AddInstruction(
            il.SetFlag(
                SHFlags::T_FLAG,
                il.Const(1, 1)
            )
        );

        il.MarkLabel(falseLabel);
        break;
    }

    // Arithmetic

    case SHOpCode::op_add:
        il.AddInstruction(
            il.SetRegister(
                4,
                get_reg(insn, 1),
                il.Add(
                    4,
                    create_op(il, insn, 0, true),
                    create_op(il, insn, 1)
                )
            )
        );
        break;

    case SHOpCode::op_sub:
        il.AddInstruction(
            il.SetRegister(
                4,
                get_reg(insn, 1),
                il.Sub(
                    4,
                    create_op(il, insn, 1),
                    create_op(il, insn, 0)
                )
            )
        );
        break;

    // Shift operations
    case SHOpCode::op_shar: {
        if (insn.operands.empty()) {
            LogError("Invalid Instruction: 0x%x", insn.addr);
            break;
        }

        auto reg_op = insn.operands[0];
        auto reg_expr = il.Register(reg_op.op_size, reg_op.reg);

        il.AddInstruction(
            il.And(
                4,
                reg_expr,
                il.Const(4, 0x1),
                SHFlagGroups::IL_FLAGWRITE_ALL
            )
        );

        il.AddInstruction(
            il.SetRegister(
                4,
                reg_op.reg,
                il.ArithShiftRight(
                    4,
                    reg_expr,
                    il.Const(4, 1)
                )
            )
        );

        break;
    }

    case SHOpCode::op_shll:
    case SHOpCode::op_shal: {
        if (insn.operands.empty()) {
            LogError("Invalid Instruction: 0x%x", insn.addr);
            break;
        }

        auto reg_op = insn.operands[0];
        auto reg_expr = il.Register(reg_op.op_size, reg_op.reg);

        il.AddInstruction(
            il.SetFlag(
                SHFlags::T_FLAG,
                il.And(
                    4,
                    reg_expr,
                    il.Const(4, 0x80000000)
                )
            )
        );

        il.AddInstruction(
            il.SetRegister(
                reg_op.op_size,
                reg_op.reg,
                il.ShiftLeft(
                    4,
                    reg_expr,
                    il.Const(4, 1)
                )
            )
        );
        break;
    }
    case SHOpCode::op_shll2:
    case SHOpCode::op_shll8:
    case SHOpCode::op_shll16: {
        if (insn.operands.empty()) {
            LogError("Invalid Instruction: 0x%x", insn.addr);
            break;
        }
        auto reg_op = insn.operands[0];

        uint8_t shift_size = 2;
        if (insn.opcode == SHOpCode::op_shll8) {
            shift_size = 8;
        } else if (insn.opcode == SHOpCode::op_shll16) {
            shift_size = 16;
        }

        il.AddInstruction(
            il.SetRegister(
                4,
                reg_op.reg,
                il.ShiftLeft(
                    4,
                    il.Register(reg_op.op_size, reg_op.reg),
                    il.Const(4, shift_size)
                )
            )
        );
        break;
    }

    case SHOpCode::op_shlr: {
        if (insn.operands.empty()) {
            LogError("Invalid Instruction: 0x%x", insn.addr);
            break;
        }

        auto reg_op = insn.operands[0];
        auto reg_expr = il.Register(reg_op.op_size, reg_op.reg);

        il.AddInstruction(
            il.And(
                4,
                reg_expr,
                il.Const(4, 0x1),
                SHFlagGroups::IL_FLAGWRITE_ALL
            )
        );
        il.AddInstruction(
            il.SetRegister(
                4,
                reg_op.reg,
                il.ArithShiftRight(
                    4,
                    reg_expr,
                    il.Const(4, 1)
                )
            )
        );
        break;
    }

    case SHOpCode::op_shlr2:
    case SHOpCode::op_shlr8:
    case SHOpCode::op_shlr16: {
        if (insn.operands.empty()) {
            LogError("Invalid Instruction: 0x%x", insn.addr);
            break;
        }
        auto reg_op = insn.operands[0];

        uint8_t shift_size = 2;
        if (insn.opcode == SHOpCode::op_shlr8) {
            shift_size = 8;
        } else if (insn.opcode == SHOpCode::op_shlr16) {
            shift_size = 16;
        }

        il.AddInstruction(
            il.SetRegister(
                4,
                reg_op.reg,
                il.ArithShiftRight(
                    4,
                    il.Register(reg_op.op_size, reg_op.reg),
                    il.Const(4, shift_size)
                )
            )
        );
        break;
    }

    // System Control
    case SHOpCode::op_clrmac:
        il.AddInstruction(
            il.SetRegister(
                4,
                SHReg::MACH,
                il.Const(4, 0)
            )
        );
        il.AddInstruction(
            il.SetRegister(
                4,
                SHReg::MACL,
                il.Const(4, 0)
            )
        );
        break;

    case SHOpCode::op_clrt:
        il.AddInstruction(
            il.SetFlag(SHFlags::T_FLAG, il.Const(1, 0))
        );
        break;

    case SHOpCode::op_sts_l:
    case SHOpCode::op_sts:
    case SHOpCode::op_stc_l:
    case SHOpCode::op_stc:
    case SHOpCode::op_lds_l:
    case SHOpCode::op_lds:
    case SHOpCode::op_ldc_l:
    case SHOpCode::op_ldc:
        lift_mov(il, insn, false, 2, 4);
        break;

    case SHOpCode::op_sett:
        il.AddInstruction(
            il.SetFlag(SHFlags::T_FLAG, il.Const(1, 1))
        );
        break;

    case SHOpCode::op_trapa:
        // TODO: Model the register edits trapa performs,
        // SH1 / SH2 and different from SH3 / SH4 so will need a 'mode check'
        il.AddInstruction(
            il.SystemCall()
        );
        break;

    // case SHOpCode::op_sts_l:



    // Branches

    // - cond branches
    case SHOpCode::op_bt:
    case SHOpCode::op_bt_s:
    case SHOpCode::op_bf:
    case SHOpCode::op_bf_s: {
        LowLevelILLabel trueLabel, falseLabel;

        ExprId cond = 0;
        if (insn.opcode == SHOpCode::op_bf || insn.opcode == SHOpCode::op_bf_s) {
            cond = il.FlagCondition(LLFC_NE);
        } else {
            cond = il.FlagCondition(LLFC_E);
        }

        il.AddInstruction(
            il.If(
                cond,
                trueLabel,
                falseLabel
            )
        );

        il.MarkLabel(trueLabel);
        // Add slot for delay instructions to be placed here.
        il.AddInstruction(
            il.Nop()
        );
        il.AddInstruction(
            il.Jump(
                create_op(il, insn, 0)
            )
        );

        il.MarkLabel(falseLabel);

        break;
    }

    // - jumps
    case SHOpCode::op_bra:
        il.AddInstruction(
            il.Jump(il.Const(4, insn.operands[0].imm))
        );
        break;
    case SHOpCode::op_jmp:
        il.AddInstruction(
            il.Jump(create_op(il, insn, 0))
        );
        break;
    case SHOpCode::op_braf:
        il.AddInstruction(
            il.Jump(
                il.Add(
                    4,
                    create_op(il, insn, 0),
                    il.Add(
                        4,
                        il.Const(4, insn.addr),
                        il.Const(4, 4)
                    )
                )
            )
        );
        break;

    // - calls
    case SHOpCode::op_bsr:
    case SHOpCode::op_jsr:
    case SHOpCode::op_jsr_n:
        il.AddInstruction(
            il.Call(
                create_op(il, insn, 0)
            )
        );
        break;
    case SHOpCode::op_bsrf:
        il.AddInstruction(
            il.Call(
                il.Add(
                    4,
                    create_op(il, insn, 0),
                    il.Add(
                        4,
                        il.Const(4, insn.addr),
                        il.Const(4, 4)
                    )
                )
            )
        );
        break;

    // returns
    case SHOpCode::op_rts:
    case SHOpCode::op_rts_n:
        il.AddInstruction(
            il.Return(
                il.Register(4, SHReg::PR)
            )
        );
        break;

    case SHOpCode::op_rtv_n:
        il.AddInstruction(
            il.SetRegister(
                4,
                SHReg::R0,
                create_op(il, insn, 0)
            )
        );
        il.AddInstruction(
            il.Return(
                il.Register(4, SHReg::PR)
            )
        );
        break;

    // Floating point

    case SHOpCode::op_fmov:
        lift_mov(il, insn, false, 1, 4);
        break;

    case SHOpCode::op_fmov_s:
        lift_mov(il, insn, false, 2, 4);
        break;

    case SHOpCode::op_fmov_d:
        lift_mov(il, insn, false, 3, 8);
        break;

    case SHOpCode::op_flds:
    case SHOpCode::op_fsts:
        il.AddInstruction(
            il.SetRegister(
                4,
                get_reg(insn, 1),
                create_op(il, insn, 0)
            )
        );
        break;

    // Misc
    case SHOpCode::op_nop:
        il.AddInstruction(il.Nop());
        break;

    default:
        il.AddInstruction(il.Unimplemented());
        break;
    }
    return;
}