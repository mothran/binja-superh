import os
import sys

from lxml import html
import requests


def fetch():
    # cache the .html into the build/ dir
    html_cache_path = os.path.join("build", "sh_insns.html")
    if not os.path.exists(html_cache_path):
        page = requests.get('http://www.shared-ptr.com/sh_insns.html')
        page_data = page.content

        with open(html_cache_path, "w") as fd:
            fd.write(page_data.decode("utf-8"))
    else:
        with open(html_cache_path, "r") as fd:
            page_data = fd.read()

    tree = html.fromstring(page_data)

    data = list()

    for row in tree.xpath("//div[@class='col_cont']"):
        insn_class = row.xpath("./div[@class='col_cont_1']/text()")[0]
        insn_text = row.xpath("./div[@class='col_cont_2']/text()")[0]
        desc_text = row.xpath("./div[@class='col_cont_3']/text()")[0]
        is_delay = False
        if "Delayed branch" in desc_text:
            is_delay = True

        bit_pat = row.xpath("./div[@class='col_cont_4']/text()")[0]
        bit_pat = bit_pat.replace(" ", "")
        insn_text = insn_text.replace("\t\t", " ").replace("\t", " ")

        # TODO: resolve duplex instructions
        #  eg: padd-pmuls and psub-pmuls
        if "\n" in insn_text:
            continue

        insn_text = ' '.join(insn_text.split())
        data.append( (insn_text, bit_pat, is_delay) )

    return data

registers = [
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
    "END_REG"
]

replace_regs = [
    "R0",
    "R15",
    "GBR",
    "TBR",
    "SR",
    "VBR",
    "MOD",
    "RE",
    "RS",
    "SGR",
    "SSR",
    "SPC",
    "DBR",
    "MACH",
    "MACL",
    "PR",
    "DSR",
    "A0",
    "X0",
    "X1",
    "Y0",
    "Y1",
    "PC",
    "FPSCR",
    "FPUL",
    "XMTRX"
]

def parse(data):
    output = list()

    print("#pragma once")
    print("#include <vector>")
    print("#include <optional>")
    print("#include <sstream>")
    print((
        "inline std::string int_to_hex(uint32_t value) {\n"
        "    std::stringstream stream;\n"
        "    stream << \"0x\" << std::hex << value;\n"
        "    return stream.str();\n"
        "}\n"
    ))
    print((
        "inline uint32_t label_disp(uint32_t d, uint32_t addr, uint32_t patt, uint32_t mask) {\n"
        "   int32_t disp = 0;\n"
        "   if ((d & patt) == 0)\n"
        "       disp = mask & d;\n"
        "   else\n"
        "       disp = ~mask | d;\n"
        # "   printf(\"%d\\n\", disp);"
        "   return (disp << 1) + 4 + addr;\n"
        "}\n"
    ))

    output.append("\ninline std::optional<SHInsn> disasm_one(uint16_t insn, uint32_t addr) {")
    opcode_list = list()

    for elm in data:
        (insn_text, bit_pat, is_delay) = elm

        tokens = list()
        if insn_text.startswith("dcf") or insn_text.startswith("dct"):
            cmd = ' '.join(insn_text.split(" ")[0:2])
        else:
            cmd = insn_text.split(" ")[0]

        cmd_enum = cmd.replace("/", "_").replace(".", "_").replace(" ", "_")
        cmd_enum = f"op_{cmd_enum}"

        if cmd_enum not in opcode_list:
            opcode_list.append(cmd_enum)

        tokens.append(f"{{InstructionToken, \"{cmd}\"}}")
        tokens.append("{TextToken, \" \"}")

        args_text = insn_text[len(cmd):].lstrip()

        # Fixup lds.l (bit pattern says 'n' but insn text says 'm' reg)
        if cmd == "lds.l" and "nnnn" in bit_pat:
            bit_pat = bit_pat.replace("nnnn", "mmmm")

        if "," in args_text:
            raw_args = args_text.split(",")
        else:
            if len(args_text) == 0:
                raw_args = list()
            else:
                raw_args = [args_text]

        oper_width = 0
        if "." in cmd:
            if cmd.endswith(".b"):
                oper_width = 1
            elif cmd.endswith(".w"):
                oper_width = 2
            elif cmd.endswith(".l"):
                oper_width = 4
            elif cmd == "fmov.s":
                oper_width = 4
            elif cmd == "fmov.d":
                oper_width = 8

        arg_count = len(raw_args)

        arg_objs = list()

        nibbles = [bit_pat[0:4], bit_pat[4:8], bit_pat[8:12], bit_pat[12:16]]
        insn_size = 2
        if len(bit_pat) > 16:
            nibbles.extend([bit_pat[16:20], bit_pat[20:24], bit_pat[24:28], bit_pat[28:32]])
            insn_size = 4

        inst = mask = ''
        for b in nibbles:
            if b[0] in '01':
                x = 0
                if b[0] == '1':
                    x = x + 8
                if b[1] == '1':
                    x = x + 4
                if b[2] == '1':
                    x = x + 2
                if b[3] == '1':
                    x = x + 1
                inst = inst + hex(x)[2]
                mask = mask + 'f'
            else:
                inst = inst + '0'
                mask = mask + '0'

        n = nshift = 0
        if bit_pat[4] == 'n':
            n |= 0x0f00
            nshift = 8
        if bit_pat[8] == 'n':
            n |= 0x00f0
            nshift = 4
        elif bit_pat[9] == 'n': # for Rn_BANK
            n |= 0x0070
            nshift = 4

        m = mshift = 0
        if bit_pat[4] == 'm':
            m |= 0x0f00
            mshift = 8
        elif bit_pat[8] == 'm':
            m |= 0x00f0
            mshift = 4
        elif bit_pat[9] == 'm': # for Rm_BANK
            m |= 0x0070
            mshift = 4

        imm = ishift = 0
        if bit_pat[8] == 'i':
            imm |= 0x00f0
            ishift = 4
        if bit_pat[12] == 'i':
            imm |= 0x000f
            ishift = 0
        if bit_pat[13] == "i":
            imm |= 0x0007
            ishift = 0

        disp = 0
        if bit_pat[12] == 'd':
            disp |= 0x000f
            if bit_pat[8] == 'd':
                disp |= 0x00f0
                if bit_pat[4] == 'd':
                    disp |= 0x0f00


        if insn_size == 4 and bit_pat[20] == 'd':
            disp |= 0x00f00000
            if bit_pat[24] == 'd':
                disp |= 0x0f000000
                if bit_pat[28] == 'd':
                    disp |= 0xf0000000

        for i, arg in enumerate(raw_args):
            is_ref = False
            is_pair = False
            mod_reg = 0

            # Leading addons
            if arg.startswith("@("):
                arg = arg[2:]
                tokens.append("{TextToken, \"@(\"}")
                is_pair = True
                is_ref = True
            if arg.startswith("@@("):
                arg = arg[3:]
                tokens.append("{TextToken, \"@@(\"}")
                is_pair = True
                is_ref = True
            if arg.startswith("@-"):
                arg = arg[2:]
                tokens.append("{TextToken, \"@-\"}")
                is_ref = True
                assert oper_width != 0, f"@- used without a operation width defined: {arg}"
                mod_reg = -oper_width

            if arg.startswith("@"):
                arg = arg[1:]
                tokens.append("{TextToken, \"@\"}")
                is_ref = True

            tailing_tokens = list()
            # Trailing addons
            if is_ref and arg.endswith("+"):
                assert oper_width != 0, f"@**+ used without a operation width defined: {cmd} {arg}"
                mod_reg = oper_width
                arg = arg[:-1]
                tailing_tokens.append("{TextToken, \"+\"}")

            if arg.endswith(")"):
                arg = arg[:-1]
                tailing_tokens.append("{TextToken, \")\"}")

            op_type = None
            is_label = False
            op_size = 0

            if arg == "Rn":
                op_type = "OpType::REG"
                op_str = f"((insn & 0x{n:x}) >> 0x{nshift:x})"
                fmt_str = f"R0 + {op_str}"
                op_size = 4
                tokens.append(f"{{RegisterToken, \"R\" + std::to_string({op_str}) }}")
            elif arg == "Rm":
                op_type = "OpType::REG"
                op_str = f"((insn & 0x{m:x}) >> 0x{mshift:x})"
                fmt_str = f"R0 + {op_str}"
                op_size = 4
                tokens.append(f"{{RegisterToken, \"R\" + std::to_string({op_str}) }}")
            elif arg == "Rn_BANK":
                op_type = "OpType::REG"
                op_str = f"((insn & 0x{n:x}) >> 0x{nshift:x})"
                fmt_str = f"R0_BANK + {op_str}"
                op_size = 4
                tokens.append(f"{{RegisterToken, \"R\" + std::to_string({op_str}) + \"_BANK\" }}")
            elif arg == "Rm_BANK":
                op_type = "OpType::REG"
                op_str = f"((insn & 0x{m:x}) >> 0x{mshift:x})"
                fmt_str = f"R0_BANK + {op_str}"
                op_size = 4
                tokens.append(f"{{RegisterToken, \"R\" + std::to_string({op_str}) + \"_BANK\" }}")
            elif arg == "FRn":
                op_type = "OpType::REG"
                op_str = f"((insn & 0x{n:x}) >> 0x{nshift:x})"
                fmt_str = f"FR0 + {op_str}"
                op_size = 4
                tokens.append(f"{{RegisterToken, \"FR\" + std::to_string({op_str}) }}")
            elif arg == "FRm":
                op_type = "OpType::REG"
                op_str = f"((insn & 0x{m:x}) >> 0x{mshift:x})"
                fmt_str = f"FR0 + {op_str}"
                op_size = 4
                tokens.append(f"{{RegisterToken, \"FR\" + std::to_string({op_str}) }}")
            elif arg == "DRn":
                op_type = "OpType::REG"
                op_str = f"((insn & 0x{n:x}) >> 0x{nshift:x})"
                fmt_str = f"DR0 + {op_str}"
                op_size = 4
                tokens.append(f"{{RegisterToken, \"DR\" + std::to_string({op_str}) }}")
            elif arg == "DRm":
                op_type = "OpType::REG"
                op_str = f"((insn & 0x{m:x}) >> 0x{mshift:x})"
                fmt_str = f"DR0 + {op_str}"
                op_size = 4
                tokens.append(f"{{RegisterToken, \"DR\" + std::to_string({op_str}) }}")
            elif arg == "XDn":
                op_type = "OpType::REG"
                op_str = f"((insn & 0x{n:x}) >> 0x{nshift:x})"
                fmt_str = f"DR0 + {op_str}"
                op_size = 4
                tokens.append(f"{{RegisterToken, \"DR\" + std::to_string({op_str}) }}")
            elif arg == "XDm":
                op_type = "OpType::REG"
                op_str = f"((insn & 0x{m:x}) >> 0x{mshift:x})"
                fmt_str = f"XD0 + {op_str}"
                op_size = 4
                tokens.append(f"{{RegisterToken, \"XD\" + std::to_string({op_str}) }}")
            elif arg == "FVn":
                op_type = "OpType::REG"
                op_str = f"((insn & 0x{n:x}) >> 0x{nshift:x})"
                fmt_str = f"FV0 + {op_str}"
                op_size = 4
                tokens.append(f"{{RegisterToken, \"FV\" + std::to_string({op_str}) }}")
            elif arg == "FVm":
                op_type = "OpType::REG"
                op_str = f"((insn & 0x{m:x}) >> 0x{mshift:x})"
                fmt_str = f"FV0 + {op_str}"
                op_size = 4
                tokens.append(f"{{RegisterToken, \"FV\" + std::to_string({op_str}) }}")

            elif arg == "disp" or arg == "disp8" or arg == "disp12" or arg == "label":
                if arg == "disp":
                    if cmd == "bra" or cmd == "bsr":
                        op_size = 2
                    else:
                        op_size = 1
                elif arg == "disp8":
                    op_size = 1
                elif arg == "disp12":
                    op_size = 2
                elif arg == "label":
                    op_size = 2

                op_type = "OpType::DISP"
                if arg == "label":
                    is_label = True

                if is_label:
                    patt = 0x80
                    if disp > 0xff:
                        patt = 0x800
                    fmt_str = f"(label_disp(insn & 0x{disp:x}, addr, {patt}, {disp}))"
                else:
                    fmt_str = f"(insn & 0x{disp:x})"

                tokens.append(f"{{PossibleAddressToken, int_to_hex({fmt_str})}}")

            elif arg == "#imm" or arg == "#imm3" or arg == "#imm20":
                if arg == "#imm" or arg == "#imm3":
                    op_size = 1
                elif arg == "#imm20":
                    op_size = 3

                fmt_str = f"(insn & 0x{imm:x})"
                op_type = "OpType::IMM"
                tokens.append(f"{{PossibleAddressToken, int_to_hex({fmt_str})}}")
            elif arg in replace_regs:
                op_type = "OpType::REG"
                fmt_str = arg
                op_size = 4
                tokens.append(f"{{RegisterToken, \"{fmt_str}\"}}")
            else:
                # print(f"Unknown arg: {arg}", file=sys.stderr)
                # fmt_str = arg
                op_type = "OpType::UNKNOWN"
                fmt_str = "0"
                tokens.append(f"{{TextToken, \"{fmt_str}\"}}")

            tokens.extend(tailing_tokens)
            if i < (arg_count - 1):
                tokens.append("{OperandSeparatorToken, \", \"}")

            is_ref_str = ""
            is_pair_str = ""
            if is_ref:
                is_ref_str = "true"
            else:
                is_ref_str = "false"

            if is_pair:
                is_pair_str = "true"
            else:
                is_pair_str = "false"

            if is_label:
                is_label_str = "true"
            else:
                is_label_str = "false"

            if "REG" in op_type:
                arg_objs.append(f"SHOper({op_type}, SHReg({fmt_str}), 0, {is_ref_str}, {is_pair_str}, {is_label_str}, {mod_reg}, {op_size})")
            else:
                reg_str = "SHReg::InvalidReg"
                arg_objs.append(f"SHOper({op_type}, {reg_str}, {fmt_str}, {is_ref_str}, {is_pair_str}, {is_label_str}, {mod_reg}, {op_size})")



        args_str =  ',\n                '.join(arg_objs)
        token_str = ',\n                '.join(tokens)

        if insn_size == 4:
            continue

        is_delay = f"{is_delay}".lower()

        fmt = (
            f"    if ((insn & 0x{mask}) == 0x{inst}) {{\n"
            f"        return SHInsn(\n"
            f"            SHOpCode::{cmd_enum},\n"
            f"            {{\n                {token_str}\n            }},\n"
            f"            {{\n                {args_str}\n            }},\n"
            f"            {is_delay},\n"
            f"            {insn_size},\n"
            f"            addr\n"
            f"        );\n"
            f"    }}\n"

        )

        output.append(fmt)

    print("\nenum class SHOpCode {")
    for opcode in opcode_list:
        print(f"    {opcode},")
    print("};")

    print("\nenum SHReg : uint32_t {")
    count = 0
    for register in registers:
        print(f"    {register} = {count},")
        count += 1
    print(f"    InvalidReg  = {count}")
    print("};")

    print("static const char *sh_reg_strs[] = {")
    for register in registers:
        print(f"    \"{register}\",")
    print("    \"InvalidReg\"")
    print("};")

    output.append("   return {};\n")
    output.append("}")
    for elm in output:
        print(elm)

data = fetch()
parse(data)