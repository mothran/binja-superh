# Binaryninja SuperH (sh4) Architecture

## Setup

### Build

```bash
mkdir build/
cd build/
# clang is optional but prefered
cmake -DCMAKE_C_COMPILER=`which clang` -DCMAKE_CXX_COMPILER=`which clang++` -DCMAKE_BUILD_TYPE=Release -DBN_INSTALL_BIN_DIR=/path/to/binaryninja ..
make sh-all
```

### Test
```bash
cd build/
ctest # or 'make test'
```

### Install

```bash
cd build/
ln -s `pwd`/libarch_superh.so ~/.binaryninja/plugins/libarch_superh.so
mkdir -p ~/.binaryninja/types/platform/
ln -s `pwd`../types/linux-superh.c ~/.binaryninja/types/platform/linux-superh.c
```

### Regenerate SH4 disassembler:

```bash
cd build/
make gen-decoder
```

## Helper Utility

`sh_disasm` is a simple test application used to validate the disassembly for a given superh4 instruction + address

```bash
cd build/
./sh_disasm beaf 0x403d4e
# sh_disasm <hex_encoded_insn_bytes> <address>
```