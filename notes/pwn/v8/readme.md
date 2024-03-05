# V8 Internals 101

<div class="hidden">
    <details>
        <summary>Keywords</summary>
          V8
    </details>
</div>

To follow along, it is recommended to build `d8` with debug mode. Steps on how
to build `d8` can be found [here](#building-d8-for-debugging)

## Pointer Compression

In V8, pointer to an object is tagged with `1` on the least significant bit (LSB).
This is done to distinguish between immediate values and pointer. Small immediate
integer (SMI) are stored in 32-bit memory space with the LSB always set to `0`.

The pointer itself is 32-bit wide which serves as an offset from the `isolate_root`.
This is how sandboxing works in V8 heap. V8 would sum up `isolate_root` and the
32-bit offset value to get the actual memory address in the process.

In the example below, we could see that the `elements` pointer is `0x2932000006cd`.
The `isolate_root` is `0x293200000000`, while the lower 32-bit, `0x000006cd` is
the offset and is the only value stored inside the heap.

> [!NOTE]
> Remember to subtract the pointer value by 1 when inspecting inside debugger

```console
$ ./d8 --allow-natives-syntax
d8> let arr = [];
undefined
d8> %DebugPrint(arr);
DebugPrint: 0x2932001c9411: [JSArray]
 - map: 0x2932000ce6b1 <Map[16](PACKED_SMI_ELEMENTS)> [FastProperties]
 - prototype: 0x2932000ce925 <JSArray[0]>
 - elements: 0x2932000006cd <FixedArray[0]> [PACKED_SMI_ELEMENTS]
 - length: 0
 - properties: 0x2932000006cd <FixedArray[0]>
 - All own properties (excluding elements): {
    0x293200000d41: [String] in ReadOnlySpace: #length: 0x29320030f6f9 <AccessorInfo name= 0x293200000d41 <String[6]: #length>, data= 0x293200000061 <undefined>> (const accessor descriptor), location: descriptor
 }
[snip]
```

Further details on pointer compression can be found on this [V8 blog](https://v8.dev/blog/pointer-compression).


## JSArray

First, let's take a look at how arrays are structured inside memory using GDB
for this snippet of code.

```js
let arr = [1.1, 2.2, 3.3, 4.4]
```

```sh
gdb -ex 'run' --args './d8 --allow-natives-syntax --shell ./script.js'
```

- `--allow-natives-syntax`: allow us to invoke built-in function, e.g., `%DebugPrint`
- `--shell`: drop into interactive mode after executing `script.js`

```console
d8> %DebugPrint(arr)
DebugPrint: 0x3349001c94ad: [JSArray]
 - map: 0x3349000cefb1 <Map[16](PACKED_DOUBLE_ELEMENTS)> [FastProperties]
 - prototype: 0x3349000ce925 <JSArray[0]>
 - elements: 0x3349001c9485 <FixedDoubleArray[4]> [PACKED_DOUBLE_ELEMENTS]
 - length: 4
 - properties: 0x3349000006cd <FixedArray[0]>
 - All own properties (excluding elements): {
    0x334900000d41: [String] in ReadOnlySpace: #length: 0x33490030f6f9 <AccessorInfo name= 0x334900000d41 <String[6]: #length>, data= 0x334900000061 <undefined>> (const accessor descriptor), location: descriptor
 }
 - elements: 0x3349001c9485 <FixedDoubleArray[4]> {
           0: 1.1
           1: 2.2
           2: 3.3
           3: 4.4
 }
```

Inspecting the object directly in debugger, we could see that there are some
familiar values `0xcefb1`, `0x6cd`, `0x1c9485`

```console
gef> tele 0x4f6001c94ad-0x1
0x3349001c94ac|+0x0000|+000: 0x000006cd000cefb1
0x3349001c94b4|+0x0008|+001: 0x00000008001c9485
0x3349001c94bc|+0x0010|+002: 0x0000030600000b51
0x3349001c94c4|+0x0018|+003: 0x0000000000000000
0x3349001c94cc|+0x0020|+004: 0x0000006100000100
0x3349001c94d4|+0x0028|+005: 0x0000006100000061
0x3349001c94dc|+0x0030|+006: 0x0000006100000061
0x3349001c94e4|+0x0038|+007: 0x0000006100000061
0x3349001c94ec|+0x0040|+008: 0x0000006100000061
0x3349001c94f4|+0x0048|+009: 0x0000006100000061
```

Recall that the upper 32-bit, `0x3349`, is not present as it is the `isolate_root`
value and is stored somewhere else in the memory. Next, remember that SMI is
stored shifted to the left by 1. The length of our array is 4 and so the value 
in memory would be `4 << 1 = 0x8` which could be found at `0x3349001c94b8`.

| offset   | value    | field |
| --- | --- | --- |
| 0x00   | 0x000cefb1   | map (pointer) |
| 0x04   | 0x000006cd   | properties (pointer) |
| 0x08   | 0x001c9485   | elements (pointer) |
| 0x0c   | 0x00000008   | length (SMI) |

Inspecting the array elements via `d8` and debugger:

```console
d8> %DebugPrintPtr(0x3349001c9485)
DebugPrint: 0x3349001c9485: [FixedDoubleArray]
 - map: 0x334900000851 <Map(FIXED_DOUBLE_ARRAY_TYPE)>
 - length: 4
           0: 1.1
           1: 2.2
           2: 3.3
           3: 4.4
```

```console
gef> tele 0x3349001c9485-0x1
0x3349001c9484|+0x0000|+000: 0x0000000800000851
0x3349001c948c|+0x0008|+001: 0x3ff199999999999a
0x3349001c9494|+0x0010|+002: 0x400199999999999a
0x3349001c949c|+0x0018|+003: 0x400a666666666666
0x3349001c94a4|+0x0020|+004: 0x401199999999999a
0x3349001c94ac|+0x0028|+005: 0x000006cd000cefb1
0x3349001c94b4|+0x0030|+006: 0x00000008001c9485
0x3349001c94bc|+0x0038|+007: 0x0000030600000b51
0x3349001c94c4|+0x0040|+008: 0x0000000000000000
0x3349001c94cc|+0x0048|+009: 0x0000006100000100
```

Again we could see familiar values like `0x851` for `map` and `0x8` for `length`.
The 4 64-bit values at offset `0x8` is actually `1.1`, `2.2`, `3.3`, and `4.4`
floating numbers in hexadecimal format.

```console
gef> p/x 1.1
$1 = 0x3ff199999999999a
gef> p/x 2.2
$2 = 0x400199999999999a
gef> p/x 3.3
$3 = 0x400a666666666666
gef> p/x 4.4
$4 = 0x401199999999999a
```

At offset `0x28`, we could see that it is actually the `JSArray` object that
we inspected earlier.

## HeapNumber

Now, let's see when some of the elements changes type to `Object` and `Integer`.
The `elements` are reallocated and the floating numbers are converted into objects.

```console
d8> arr[0] = {}
d8> arr[1] = 1
d8> %DebugPrint(arr)
DebugPrint: 0x3349001c94ad: [JSArray]
 - map: 0x3349000cf031 <Map[16](PACKED_ELEMENTS)> [FastProperties]
 - prototype: 0x3349000ce925 <JSArray[0]>
 - elements: 0x3349001ca1b9 <FixedArray[4]> [PACKED_ELEMENTS]
 - length: 4
 - properties: 0x3349000006cd <FixedArray[0]>
 - All own properties (excluding elements): {
    0x334900000d41: [String] in ReadOnlySpace: #length: 0x33490030f6f9 <AccessorInfo name= 0x334900000d41 <String[6]: #length>, data= 0x334900000061 <undefined>> (const accessor descriptor), location: descriptor
 }
 - elements: 0x3349001ca1b9 <FixedArray[4]> {
           0: 0x3349001ca19d <Object map = 0x3349000c4945>
           1: 1
           2: 0x3349001ca1dd <HeapNumber 3.3>
           3: 0x3349001ca1d1 <HeapNumber 4.4>
 }
d8> %DebugPrintPtr(0x3349001ca1dd)
DebugPrint: 0x3349001ca1dd: [HeapNumber]
 - map: 0x3349000007b1 <Map[12](HEAP_NUMBER_TYPE)>
 - value: 3.3
```

Looking via debugger, this is how the new `elements` and `HeapNumber` look like
inside memory.

```console
gef> tele 0x3349001ca1b9-0x1
0x3349001ca1b8|+0x0000|+000: 0x0000000800000565
0x3349001ca1c0|+0x0008|+001: 0x00000002001ca19d
0x3349001ca1c8|+0x0010|+002: 0x001ca1d1001ca1dd

gef> tele 0x3349001ca1dd-0x1
0x3349001ca1dc|+0x0000|+000: 0x66666666000007b1
0x3349001ca1e4|+0x0008|+001: 0x000007b1400a6666
0x3349001ca1ec|+0x0010|+002: 0x400199999999999a
0x3349001ca1f4|+0x0018|+003: 0x9999999a000007b1
```

| offset   | value    | field |
| --- | --- | --- |
| 0x00   | 0x000cefb1   | map (pointer) |
| 0x04   | 0x400a666666666666   | value (3.3) |

## JSObject

Read this: <https://jhalon.github.io/chrome-browser-exploitation-1/#object-representation>

## Elements Kinds

For arrays of kind `PACKED_SMI_ELEMENTS`, `PACKED_DOUBLE_ELEMENTS`,
and `PACKED_ELEMENTS`, the elements is always allocated first which means that
it can be found on lower memory address than the `JSArray` object itself.
object.

```js
let packed_smi_arr_1 = [1]
packed_smi_arr_1.push(2.2) // now this array becomes PACKED_DOUBLE_ELEMENTS kind
packed_smi_arr_1.push({}) // now this array becomes PACKED_ELEMENTS kind

let packed_smi_arr_2 = [1]
packed_smi_arr_2.push({}) // now this array becomes PACKED_ELEMENTS kind
packed_smi_arr_2.push(2.2) // stays on PACKED_ELEMENTS kind

let packed_double_arr = [1, 2.2]
let packed_arr_1 = [{}]
let packed_arr_2 = [0, {}]
```

There are also other kind of arrays, i.e., `HOLEY_SMI_ELEMENTS`, `HOLEY_DOUBLE_ELEMENTS`,
and `HOLEY_ELEMENTS`. This are arrays that has `the_hole_value` as the element.
The `JSArray` object is located at lower memory address than the elements.

```js
let arr = Array(4)  // arr is HOLEY_SMI_ELEMENTS kind
arr[0] = 1.1        // arr transitions to HOLEY_DOUBLE_ELEMENTS kind
arr[1] = {}         // arr transitions to HOLEY_ELEMENTS kind

let foo = [1, 2.2]  // foo is PACKED_DOUBLE_ELEMENTS kind
delete foo[1]       // foo transitions to HOLEY_DOUBLE_ELEMENTS
```

Element kinds transition can be read on [this blog](https://v8.dev/blog/elements-kinds)

## References

- <https://v8.dev/blog/pointer-compression>
- <https://v8.dev/blog/elements-kinds>
- <https://jhalon.github.io/chrome-browser-exploitation-1/#object-representation>

## Appendix

### Building d8 for Debugging

```sh
git clone https://chromium.googlesource.com/chromium/tools/depot_tools.git
export PATH="$(pwd)/depot_tools:$PATH"
fetch v8
cd v8
./build/install-build-deps.sh
gclient sync
./tools/dev/v8gen.py x64.debug
ninja -C ./out.gn/x64.debug
cd ./out.gn/x64.debug
./d8
```
