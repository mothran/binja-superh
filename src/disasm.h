#pragma once
#include <string>
#include <vector>
#include <utility>
#include <cstdint>
#include <optional>

#include "binaryninjacore.h"

enum class OpType {
    REG = 0,
    IMM = 1,
    DISP = 2,
    UNKNOWN = 3
};

enum SHReg : uint32_t;

struct SHOper {
    SHOper(OpType type, SHReg reg, uint32_t imm, bool is_ref, bool is_pair, bool is_label, int8_t mod_reg, uint8_t op_size);

    OpType type;
    uint32_t imm;
    SHReg reg;
    bool is_ref;
    bool is_pair;
    bool is_label;
    int8_t mod_reg;
    uint8_t op_size;
};

using TokenVec = std::vector<std::pair<BNInstructionTextTokenType, std::string>>;

enum class SHOpCode;

struct SHInsn {
    SHInsn(SHOpCode opcode, TokenVec tokens) :
        opcode(opcode), tokens(tokens), is_delay(false) {};
    SHInsn(SHOpCode opcode, TokenVec tokens, std::vector<SHOper> ops, bool is_delay, uint8_t size, uint32_t addr) :
        opcode(opcode),
        tokens(tokens),
        operands(ops),
        is_delay(is_delay),
        size(size),
        addr(addr) {};

    SHOpCode opcode;
    TokenVec tokens;
    std::vector<SHOper> operands;
    bool is_delay;
    uint8_t size;
    uint32_t addr;
};

std::optional<SHInsn> disassemble(const uint8_t *buf, uint32_t addr, uint32_t size);

const char *get_reg_name(uint32_t reg);

#include "disasm-gen.inc"
