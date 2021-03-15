#include <cstdint>
#include <string>
#include <utility>
#include <optional>

#include "disasm.h"

SHOper::SHOper(OpType type, SHReg reg, uint32_t imm, bool is_ref, bool is_pair, bool is_label, int8_t mod_reg, uint8_t op_size) :
    type(type),
    imm(imm),
    reg(reg),
    is_ref(is_ref),
    is_pair(is_pair),
    is_label(is_label),
    mod_reg(mod_reg),
    op_size(op_size) {};

std::optional<SHInsn> disassemble(const uint8_t *buf, uint32_t addr, uint32_t size) {
    const uint16_t *insn = (const uint16_t *)buf;
    return disasm_one(*insn, addr);
}

const char *get_reg_name(uint32_t reg) {
    if (reg >= SHReg::InvalidReg) {
        return "InvalidReg";
    }
    return sh_reg_strs[reg];
}
