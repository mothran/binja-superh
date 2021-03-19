#include <iostream>
#include <cstdint>
#include <cstdlib>
#include <string>
#include <utility>
#include <vector>
#include <optional>

#include "disasm.h"

std::optional<int> char2int(char input)
{
    if(input >= '0' && input <= '9')
        return input - '0';
    if(input >= 'A' && input <= 'F')
        return input - 'A' + 10;
    if(input >= 'a' && input <= 'f')
        return input - 'a' + 10;
    return {};
}
std::vector<uint8_t> hex2bin(const char* src) {
    std::vector<uint8_t> output;
    while(*src && src[1]) {
        auto char_int_res = char2int(*src);
        auto char_int_res_2 = char2int(src[1]);

        if (!char_int_res || !char_int_res_2) {
            return {};
        }
        output.push_back((*char_int_res * 16) + *char_int_res_2);
        src += 2;
    }
    return output;
}

void print_op(SHOper &oper) {
    std::string type_str;
    if (oper.type == OpType::REG) {
        type_str = "REG";
    }
    else if (oper.type == OpType::IMM) {
        type_str = "IMM";
    }
    else if (oper.type == OpType::DISP) {
        type_str = "DISP";
    }
    else {
        type_str = "UNKNOWN";
    }

    std::cout << "  type:    " << type_str << std::endl;
    std::cout << "  reg:     " << std::to_string(oper.reg) << std::endl;
    std::cout << "  imm:     " << oper.imm << std::endl;
    std::cout << "  is_ref:  " << oper.is_pair << std::endl;
    std::cout << "  is_pair: " << oper.is_pair << std::endl;
}

int main(int argc, char **argv) {
    if (argc < 2) {
        std::cout << "Usage: " << argv[0] << " <instruction_hex, '03c09da0'> [<0xaddress>: default: 0x1000]" << std::endl;
        return 1;
    }

    auto data = hex2bin(argv[1]);
    if (!data.size()) {
        std::cout << "Invalid instruction hex" << std::endl;
        return 1;
    }

    uint32_t addr = 0x1000;
    if (argc == 3) {
        auto addr_str = std::string(argv[2]);
        addr = std::strtol(addr_str.c_str(), nullptr, 16);
    }

    auto insn_res = disassemble(data.data(), addr, data.size());
    if (!insn_res) {
        std::cout << "Failed to disasm" << std::endl;
        return 1;
    }

    auto insn = *insn_res;

    std::cout << "Insn: " << std::endl;
    std::cout << " opcode:        " << std::to_string((uint32_t)insn.opcode) << std::endl;
    std::cout << " addr:          0x" << std::hex << insn.addr << std::endl;
    std::cout << " size:          0x" << std::hex << std::to_string(insn.size) << std::endl;
    std::cout << " operand_count: " << insn.operands.size() << std::endl;
    std::cout << " is_delay:      " << insn.is_delay << std::endl;

    std::string insn_str;
    for (const auto &token : insn.tokens) {
        insn_str += token.second;
    }
    std::cout << " op_str:        " << insn_str << std::endl;

    std::cout << std::endl;
    std::cout << "Operands" << std::endl;
    for (auto &op : insn.operands) {
        print_op(op);
        std::cout << std::endl;
    }


    return 0;
}