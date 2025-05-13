# Notes

> [!WARNING]
> Work In Progress

## SMI

- The integer `4` in dart is stored as `4 << 1 = 8` in memory

## Registers

```cpp
// From <dart_v3.0.3>/runtime/vm/constants_arm64.h
// Register aliases.
const Register TMP = R16; // Used as scratch register by assembler.
const Register TMP2 = R17;
const Register PP = R27; // Caches object pool pointer in generated code.
const Register DISPATCH_TABLE_REG = R21; // Dispatch table register.
const Register CODE_REG = R24;
// Set when calling Dart functions in JIT mode, used by LazyCompileStub.
const Register FUNCTION_REG = R0;
const Register FPREG = FP; // Frame pointer register. R29
const Register SPREG = R15; // Stack pointer register.
const Register IC_DATA_REG = R5; // ICData/MegamorphicCache register.
const Register ARGS_DESC_REG = R4; // Arguments descriptor register.
const Register THR = R26; // Caches current thread in generated code.
const Register CALLEE_SAVED_TEMP = R19;
const Register CALLEE_SAVED_TEMP2 = R20;
const Register HEAP_BITS = R28; // write_barrier_mask << 32 | heap_base >> 32
const Register NULL_REG = R22; // Caches NullObject() value.
#define DART_ASSEMBLER_HAS_NULL_REG 1
// ABI for catch-clause entry point.
const Register kExceptionObjectReg = R0;
const Register kStackTraceObjectReg = R1;
```

## ABI (Calling Convention)

 Stack layout

```
(lower memory address) (top of the stack)
local_variables
saved_fp
saved_lr
arg2
arg1
arg0
(higher memory address)
```

> [!NOTE]
> arg2 above is equivalent to `getArg(this.context, 0)` in blutter_frida.js
> arg1 above is equivalent to `getArg(this.context, 1)` in blutter_frida.js
> arg0 above is equivalent to `getArg(this.context, 2)` in blutter_frida.js

Arguments are pushed onto the stack

```armasm
stp x0, x1, [x15, #0x10]  ; push arg0, arg1
...
stp x0, x1, [x15]  ; push arg2, arg3
```

### Arguments Descriptor

```
[0, 0x2, 0x2, 0x2, Null]
[
  0,
  0x2,  <== total arguments
  0x2,
  0x2,  <== number of positional arguments
  Null  <== marks end of arguments
]

[0, 0x4, 0x4, 0x2, "h", 0x2, "sl", 0x3, Null]
[
  0,
  0x4,       <== total arguments
  0x4,
  0x2,       <== number of positional arguments
  "h", 0x2,  <== argument `h` is on arg2
  "sl", 0x3, <== argument `sl` is on arg3
  Null       <== marks end of arguments
]
```

## Object Pool References

```sh
r2> "/ad/a ldr.*, \[x27, 0x6990\]"
r2> "/ad/ add.*, x27, 0x6, lsl 12;0x990\]"
```

## Subroutine Prologue

```armasm
; EnterFrame
stp fp, lr, [x15, #-0x10]!
mov fp, x15
; AllocStack(0x40)
sub x15, x15, #0x40
; SetupParameters
...  ; instruction that does x1 = fp
ldr x1, [x1, #0x18]  ; arg1 (blutter arg0)
stur x1, [x1, #-0x18]
...  ; instruction that does x2 = fp
ldr x2, [x2, #0x10]  ; arg0 (blutter arg1)
stur x2, [x2, #-0x10]
; CheckStackOverflow
ldr x16, [x26, #0x38]  ; THR::stack_limit
cmp x15, x16
b.ls 0x????  ; jump to block that calls StackOverflowSharedWithoutFPURegs
```

## Object Instantiation

```armasm
bl Allocate{class_name}Stub
```

## Object Field Access

```armasm
ldur x1, [x0, #0x7]   ; equivalent to off_8 in blutter_frida.js
ldur x2, [x0, #0xb]   ; equivalent to off_c in blutter_frida.js
ldur x3, [x0, #0xf]   ; equivalent to off_10 in blutter_frida.js
ldur x4, [x0, #0x13]  ; equivalent to off_14 in blutter_frida.js
```

## Future (Async)

```armasm
ldr x0, [x27, #0x??]  ; async return type
bl InitAsyncStub
...
bl subroutine
mov x1, x0
stur x1, [fp, #-0x80]
...
ldr x0, [fp, #-0x80]
bl AwaitStub
...
bl ReturnAsyncStub  ; if returns data, otherwise ReturnAsyncNotFutureStub (void or Future<void>)
```

## Closure/Lambda/Anonymous Function

- `AllocateClosureStub`:
  - arg0: unused (?)
  - arg1: closure
  - arg2: context

## Array/List

- `ArrayWriteBarrierStub` is always called after assigning element whose value is only known at runtime

```armasm
mov x2, 8
bl AllocateArrayStub  ; initialize array of length 4 (8/2)
stur x1, [x0, #0xf]   ; array[0]  = x1
stur x2, [x0, #0x13]  ; array[1] = x2
stur x3, [x0, #0x17]  ; array[2] = x3
stur x4, [x0, #0x1b]  ; array[3] = x4
```

## Map

- To view `Map` content as a `List`, access `off_10` field of the decompressed pointer.
  In Frida, this could be achieve by doing this: `map.add(0xf).readPointer()`

```armasm
ldur  w2, [x0, 0x57]       ; load Map object
add   x2, x2, x28, lsl 32  ; decompress pointer
str   x2, [x15]            ; <== hook here, `this.context.x2.add(0xf).readPointer()`
```

- Modified `blutter_frida.js` to print `Map` object
  ```js
  function getObjectValue(ptr, cls, depthLeft = MaxDepth) {
    switch (cls.id) {
      case CidObject:
        console.error(`Object cid should not reach here`);
        return;
      case CidNull:
        return null;
      case CidBool:
        return getDartBool(ptr, cls);
      case CidString:
        return getDartString(ptr, cls);
      case CidTwoByteString:
        return getDartTwoByteString(ptr, cls);
      case CidMint:
        return getDartMint(ptr, cls);
      case CidDouble:
        return getDartDouble(ptr, cls);
      case CidArray:
        return getDartArray(ptr, cls, depthLeft);
      case CidGrowableArray:
        return getDartGrowableArray(ptr, cls, depthLeft);
      case CidUint8Array:
        return getDartTypedArrayValues(ptr, cls, 1, (p) => p.readU8());
      case CidInt8Array:
        return getDartTypedArrayValues(ptr, cls, 1, (p) => p.readS8());
      case CidUint16Array:
        return getDartTypedArrayValues(ptr, cls, 2, (p) => p.readU16());
      case CidInt16Array:
        return getDartTypedArrayValues(ptr, cls, 2, (p) => p.readS16());
      case CidUint32Array:
        return getDartTypedArrayValues(ptr, cls, 4, (p) => p.readU32());
      case CidInt32Array:
        return getDartTypedArrayValues(ptr, cls, 4, (p) => p.readS32());
      case CidUint64Array:
        return getDartTypedArrayValues(ptr, cls, 8, (p) => p.readU64());
      case CidInt64Array:
        return getDartTypedArrayValues(ptr, cls, 8, (p) => p.readS64());
      // begin
      // add the following code
      case CidMap:
          let [_, _cls, values] = getTaggedObjectValue(ptr.add(0x10).readPointer());
          let _map = {};
          for (let i = 0; i < values.length; i += 2) {
              if (values[i] === null) {
                  continue;
              }
              _map[values[i]] = values[i + 1];
          }
          return _map;
      // end
    }

    if (cls.id < NumPredefinedCids) {
      const msg = `Unhandle class id: ${cls.id}, ${cls.name}`;
      console.log(msg);
      return msg;
    }

    if (depthLeft <= 0) {
      return "no more recursive";
    }

    // find parent tree
    let parents = [];
    let scls = Classes[cls.sid];
    while (scls.id != CidObject) {
      parents.push(scls);
      scls = Classes[scls.sid];
    }
    // get value from top parent to bottom parent
    let values = {};
    while (parents.length > 0) {
      const sscls = scls;
      scls = parents.pop();
      const parentValue = getInstanceValue(ptr, scls, sscls, depthLeft);
      values[`parent!${scls.name}`] = parentValue;
    }
    const myValue = getInstanceValue(ptr, cls, scls, depthLeft);
    Object.assign(values, myValue);
    return values;
  }
  ```

## Dart and ARM ASM Comparison

### oaepEncrypt

```dart
class Rsa {
  late KeyPair kp;
  final String oaepLabel = "oaepLabel";

  // ...

  Future<String> oaepEncrypt(String data) async {
    final result =
        await RSA.encryptOAEP(data, oaepLabel, Hash.SHA256, kp.publicKey);
    return result;
  }

  // ...

}
```

```armasm
    stp     fp, lr, [x15, -0x10]!
    mov     fp, x15
    sub     x15, x15, 0x28
    stur    x22, [fp, -8]
    mov     x0, 0
    add     x1, fp, w0, sxtw 2
    ldr     x1, [x1, 0x18]
    stur    x1, [fp, -0x18] ; Rsa object (this) -- arg0
    add     x2, fp, w0, sxtw 2
    ldr     x2, [x2, 0x10]
    stur    x2, [fp, -0x10] ; data -- arg1
    ldr     x16, [x26, 0x38]
    cmp     x15, x16
    b.ls    _label_b
_label_a:
    ldr     x0, [x27, #0x778] ; TypeArguments: <String>
    bl      InitAsyncStub
    ldur    x0, [fp, -0x18] ; load this
    ldur    w1, [x0, 7] ; load this.kp
    add     x1, x1, x28, lsl 32
    ldr     x16, [x27, 0x40] ; Sentinel
    cmp     w1, w16
    b.eq    _label_c ; check if this.kp is uninitialized
    ldur    w0, [x1, 7] ; load this.kp.off_8
    add     x0, x0, x28, lsl 32 ; int64_t arg4 ; decompress pointer
    ldur    x16, [fp, -0x10] ; load data
    stp     x0, x16, [x15] ; push arguments to the stack
    bl      encryptOAEP
    mov     x1, x0 ; Future<String>
    stur    x1, [fp, -0x10]
    bl      AwaitStub
    b       ReturnAsyncStub
_label_b:
    bl      StackOverflowSharedWithoutFPURegsStub
    b       _label_a
_label_c:
    add     x9, x27, 0xc, lsl 12
    ldr     x9, [x9, 8]
    bl      LateInitializationErrorSharedWithoutFPURegs
```

### CipherInterceptor.onRequest



## Identifying Cryptography Algorithms

### AES

- Look for AES Rijndael S-box
- Look for AES rcon (round constants) used for key scheduling
- Look for AES table

### Hash

- Look for states or constants, e.g.:
    - `0x67452301 0xEFCDAB89 0x98BADCFE 0x10325476 0xC3D2E1F0` is used in `SHA1`

> [!NOTE]
> Always count the number of states present since the same states are used in different hashing algorithm, e.g., `MD5` has 4 states which happens to be `SHA1` first 4 states out of 5


> [!NOTE]
> `SHA224` and `SHA256` shares the same constants but different states. Be careful when making judgement.

### HMAC

- Look for XOR operation with `0x5c` or `0x36`
  ```sh
  r2> "/ad/a mov.*, 0x(5c|36)$"
  0x001fb8b0   # 4: mov x17, 0x36
  0x001fb9e0   # 4: mov x17, 0x5c
  0x0040c89c   # 4: mov x2, 0x5c
  0x0040ca28   # 4: mov x2, 0x5c
  0x0040cc08   # 4: mov x2, 0x5c
  0x0041b274   # 4: mov x2, 0x36
  0x0041b418   # 4: mov x3, 0x5c
  ```

  ```armasm
      movz    x2, #0x36  ; <==
      stur    x4, [fp, #-0x10]
      stur    x3, [fp, #-0x30]
      ldur    w5, [x1, #0xb]
      add     x5, x5, x28, lsl #32
      stur    x5, [fp, #-8]
      stp     x4, x5, [x15, #8]
      str     x2, [x15]
      bl      foo
  ...
      movz    x3, #0x5c  ; <==
      ldur    x16, [fp, #-8]
      ldur    lr, [fp, #-0x10]
      stp     lr, x16, [x15, #8]
      str     x3, [x15]
      bl      foo
  ...
  foo:
      ...
      ldr     x2, [fp, #0x10]
      eor     x0, x1, x2  ; <==
  ```
- different hashing function generates different length of bytes, used this to make an educated guess of the hashing function

## Identifying Packages

- `fast_rsa`: existence of `librsa_bridge.so` file
- `encrypt` or `pointycastle`: existence of ASN1 OIDs
  ```
  List<Map<String, Object>>(135) [Map<String, Object>(3) {
    "identifierString": "1.2.840.113549.1.9.22.1",
    "readableName": "x509Certificate",
    "identifier": List<int>(8) [0x1, 0x2, 0x348, 0x1bb8d, 0x1, 0x9, 0x16, 0x1]
  }, Map<String, Object>(3) {
    "identifierString": "1.2.840.113549.1.9.22.2",
    "readableName": "sdsiCertificate",
    "identifier": List<int>(8) [0x1, 0x2, 0x348, 0x1bb8d, 0x1, 0x9, 0x16, 0x2]
  }, Map<String, Object>(3) {
    "identifierString": "1.2.840.113549.1.9.20",
    "readableName": "friendlyName",
    "identifier": List<int>(7) [0x1, 0x2, 0x348, 0x1bb8d, 0x1, 0x9, 0x14]
  }, Map<String, Object>(3) {
    "identifierString": "1.2.840.113549.1.9.21",
    "readableName": "localKeyID",
    "identifier": List<int>(7) [0x1, 0x2, 0x348, 0x1bb8d, 0x1, 0x9, 0x15]
  }, Map<String, Object>(3) {
    "identifierString": "1.2.840.113549.1.12.10.1.1",
    "readableName": "keyBag",
    "identifier": List<int>(9) [0x1, 0x2, 0x348, 0x1bb8d, 0x1, 0xc, 0xa, 0x1, 0x1]
  }, Map<String, Object>(3) {
    "identifierString": "1.2.840.113549.1.12.10.1.2",
    "readableName": "pkcs-8ShroudedKeyBag",
    "identifier": List<int>(9) [0x1, 0x2, 0x348, 0x1bb8d, 0x1, 0xc, 0xa, 0x1, 0x2]
  }, Map<String, Object>(3) {
    "identifierString": "1.2.840.113549.1.12.10.1.3",
    "readableName": "certBag",
    "identifier": List<int>(9) [0x1, 0x2, 0x348, 0x1bb8d, 0x1, 0xc, 0xa, 0x1, 0x3]
  }, Map<String, Object>(3) {
    "identifierString": "1.2.840.113549.1.12.10.1.4",
    "readableName": "crlBag",
    "identifier": List<int>(9) [0x1, 0x2, 0x348, 0x1bb8d, 0x1, 0xc, 0xa, 0x1, 0x4]
  }, ...
  ```
- `cryptography`: existence of `secretKeyData` string in `pp.txt`

## Appendix

### Blutter

- To inspect an object, we could either use compressed or decompressed pointer

### Dump

- `Sentinel` is a value used to fill uninitialized `late` object field

### References

- https://conference.hitb.org/hitbsecconf2023hkt/materials/D2%20COMMSEC%20-%20B(l)utter%20%E2%80%93%20Reversing%20Flutter%20Applications%20by%20using%20Dart%20Runtime%20-%20Worawit%20Wangwarunyoo.pdf
- https://goggleheadedhacker.com/post/intro-to-cutter
- https://goggleheadedhacker.com/blog/post/reversing-crypto-functions-aes
- https://goggleheadedhacker.com/blog/post/reversing-crypto-functions#identifying-salsa20-in-assembly
