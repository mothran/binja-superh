#pragma once

#include "disasm.h"
#include "binaryninjaapi.h"

void find_branches(SHInsn &insn, BinaryNinja::InstructionInfo &result);