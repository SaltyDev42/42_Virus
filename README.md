
# woody_woodpacker
Main objective of the project is to obfuscate/encrypt the target program, and puts our own payload in the binary to de-obfuscate/decrypt the executable, allowing it to run. \
Supported binary: ELF64 \
Encryption used: AES128 \
Tested Compiler: GCC 7.0~9.2 \
Binary type: ET_EXEC, ET_DYN

## Routine used
This is a 2 step injection, the stub, and the payload. This stub is injected after the executable segment, this segment can be identified with the type **PT_LOAD** and the flag **PF_X | PF_R**. \
The stub has 4 job:
 1. Make the payload's memory executable (BSS section)
 2. Call the payload to de-obfuscate/decrypt the program
 3. Restore the memory original rights
 4. Zero the payload memory

The step 4 is necessary because the payload will be injected into the BSS and most binary expect it to be zeroed.


The following diagram shows where injection happens: \
GCC version > 8.2.0
```
                                     +-----------------+
                                     |   elf headers   |
                                     +-----------------+
                                     | program headers |
                                     +-----------------+
                                     |       ...       |
                                     +-----------------+
                                     |  section .text  |
                                     +-----------------+   <---- stub
                                     | section .rodata |
                                     +-----------------+
                                     |  section .data  |
                                     +-----------------+
                                     |  section .bss   |   <---- payload
                                     +-----------------+
                                     | section headers |
                                     +-----------------+
                                     |       ...       |
                                     +-----------------+
```
GCC version < 8.2.0
```
                                     +-----------------+
                                     |   elf headers   |
                                     +-----------------+
                                     | program headers |
                                     +-----------------+
                                     |       ...       |
                                     +-----------------+
                                   * |  section .text  |
                                     | section .rodata |
                                     |  section .data  |
                                     +-----------------+   <---- stub
                                     |  section .bss   |   <---- payload
                                     +-----------------+
                                     | section headers |
                                     +-----------------+
                                     |       ...       |
                                     +-----------------+
* This segment contains 3 sections and has alignment page of 200k bytes in 
virtual memory which has been fragmented in newer version of gcc.
```
NOTE: The stub will not grow the executable segments, only the data segments will.

##  Installation
A makefile is provided with the following rules: `test` `all` `clean` `fclean` `re` \
Test are also included.

## Usage
```
./woody_woodpacker [-p payload path] [-d decrypt symbol name] [-e encrypt symbol name] binary
```
NOTE: the payload should be a binary, and compiled with `gcc` with the option `-c`

## Credits
To my friend gaulish who made the payload AES128 using instruction AES-NI extension.
