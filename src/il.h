#pragma once

namespace BinaryNinja {
    class Architecture;
    class LowLevelILFunction;
}
struct SHInsn;

enum SHFlagGroups {
    IL_FLAGWRITE_NONE = 0,
    IL_FLAGWRITE_ALL = 1
};

enum SHFlags {
    NONE = 0,
    T_FLAG = 1,
    LDST = 2,
};

void lift(BinaryNinja::Architecture* arch, SHInsn &insn, BinaryNinja::LowLevelILFunction &il);