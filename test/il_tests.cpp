#define CATCH_CONFIG_MAIN
#include <cstdint>
#include <iterator>

#include <catch2/catch.hpp>

#include "binaryninjaapi.h"
#include "lowlevelilinstruction.h"

using namespace BinaryNinja;

std::string strinify_il_func(Architecture *arch, LowLevelILFunction &il_func) {
    std::string output;
    for(size_t i = 0; i < il_func.GetInstructionCount(); i++) {
        std::vector<InstructionTextToken> tokens;
        il_func.GetInstructionText(nullptr, arch, i, tokens);
        for (const auto &token : tokens) {
            output += token.text;
        }
        output += "; ";
    }

    return output;
}

template<uint64_t N>
void run_test(Ref<Architecture> arch, const uint8_t (&bytes)[N], std::string match_str, uint64_t addr = 0x1000) {
    REQUIRE(arch);
    auto il = LowLevelILFunction(arch, nullptr);
    auto length = N;
    auto ret = arch->GetInstructionLowLevelIL(bytes, addr, length, il);
    REQUIRE(ret);
    auto il_str = strinify_il_func(arch, il);
    REQUIRE(il_str == match_str);
}

class LLILTestsFixture {
  private:
    static int uniqueID;
  protected:
    Ref<Architecture> arch;
  public:
    LLILTestsFixture() {
        SetBundledPluginDirectory(GetUserPluginDirectory());
        InitPlugins();
        arch = Architecture::GetByName("superh");
    }
  protected:
    int getID() { return ++uniqueID; }
};
int LLILTestsFixture::uniqueID = 0;

// Mov's

TEST_CASE_METHOD(LLILTestsFixture, "mov (reg)", "[mov]") {
    run_test(arch,
        // mov R0, R8
        {0x03, 0x68},
        "R8 = R0; "
    );
}

TEST_CASE_METHOD(LLILTestsFixture, "mov (imm)", "[mov]") {
    run_test(arch,
        // mov 0x0, R5
        {0x00, 0xe5},
        "R5 = sx.d(0); "
    );
}

// Arithmetic

TEST_CASE_METHOD(LLILTestsFixture, "add (regs)", "[arithmetic]") {
    run_test(arch,
        // add R12, R1
        {0xcc, 0x31},
        "R1 = R12 + R1; "
    );
}
TEST_CASE_METHOD(LLILTestsFixture, "sub (regs)", "[arithmetic]") {
    run_test(arch,
        // sub R4, R1
        {0x48, 0x31},
        "R1 = R1 - R4; "
    );
}

// Other

TEST_CASE_METHOD(LLILTestsFixture, "delayslot - plt", "[other]") {
    run_test(arch,
        // jmp @R0
        // mov R1, R0

        {0x2b, 0x40, 0x13, 0x60},
        "nop; R0 = R1; jump(R0); "
    );
}
