#include <cstdint>
#include <memory>
#include <vector>

#include "disasm.h"
#include "binaryninjacore.h"
#include "binaryninjaapi.h"
#include "branches.h"

using namespace BinaryNinja;

void find_branches(SHInsn &insn, InstructionInfo &result) {
    uint32_t pc = insn.addr + insn.size;
    if (insn.is_delay) {
        pc += 2;
    }

    switch (insn.opcode) {
    case SHOpCode::op_bf:
    case SHOpCode::op_bf_s:
        result.AddBranch(BNBranchType::FalseBranch, insn.operands[0].imm, nullptr, insn.is_delay);
        result.AddBranch(BNBranchType::TrueBranch, pc, nullptr, insn.is_delay);
        break;
    case SHOpCode::op_bt:
    case SHOpCode::op_bt_s:
        result.AddBranch(BNBranchType::TrueBranch, insn.operands[0].imm, nullptr, insn.is_delay);
        result.AddBranch(BNBranchType::FalseBranch, pc, nullptr, insn.is_delay);
        break;
    case SHOpCode::op_bra:
        result.AddBranch(BNBranchType::UnconditionalBranch, insn.operands[0].imm, nullptr, insn.is_delay);
        break;
    case SHOpCode::op_braf:
    case SHOpCode::op_jmp:
    case SHOpCode::op_jsr:
    case SHOpCode::op_jsr_n:
        result.AddBranch(BNBranchType::UnresolvedBranch, 0, nullptr, insn.is_delay);
        break;
    case SHOpCode::op_bsrf:
        result.AddBranch(BNBranchType::CallDestination, 0, nullptr, insn.is_delay);
        break;
    case SHOpCode::op_bsr:
        result.AddBranch(BNBranchType::CallDestination, insn.operands[0].imm, nullptr, insn.is_delay);
        break;
    case SHOpCode::op_rts:
    case SHOpCode::op_rts_n:
    case SHOpCode::op_rtv_n:
    case SHOpCode::op_rte:
        result.AddBranch(BNBranchType::FunctionReturn, 0, nullptr, insn.is_delay);
        break;
    case SHOpCode::op_trapa:
        result.AddBranch(BNBranchType::SystemCall);
        break;
    default:
        break;
    }
}