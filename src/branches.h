#pragma once

struct SHInsn;
namespace BinaryNinja { struct InstructionInfo; }

void find_branches(SHInsn &insn, BinaryNinja::InstructionInfo &result);