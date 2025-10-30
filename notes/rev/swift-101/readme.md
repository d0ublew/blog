# Notes

> [!WARNING]
> Work In Progress

- witness table is basically vtable (?)

## String

### Inlined

- For string size less than 16 bytes
- pattern:
  - offset 0 (`str` field): the string bytes itself (0-7)
  - offset 8 (`bridgeObject` field): most significant nibble is `0xe` followed by another nibble that represents the string length (without null byte) and the rest are the string bytes (8-15)

```c
  // "Invalid data" string inlined
  auVar3.bridgeObject = (void *)0xec00000061746164;
  auVar3.str = (char *)0x2064696c61766e49;
```

Filter using radare2 (not really reliable)

```sh
r2> "/ad/a movk .*, .*, lsl 16"
r2> "/ad/a movk .*, .*, lsl 32"
r2> "/ad/a movk .*, .*, lsl 48"
```

### Not Inlined

- For string size 16 bytes and above
- pattern:
  - offset 0 (`str` field): most significant nibble is `0xd` and the rest represents the string length (including null byte)
  - offset 8 (`bridgeObject` field): most significant nibble is `0x8` and the rest is pointer to the string, off by 0x20 bytes

```c
    // string of length 0x10 @ (0x100008210+0x20)
    local_30.str = (char *)0xd000000000000010;
    local_30.bridgeObject = (void *)0x8000000100008210;
```

```
     10000822f 00            ds        ""
     100008230 4b 65 79      ds        "Keychain error: "
               63 68 61
               69 6e 20
     100008241 00            ds        ""
```

Filter using radare2

```sh
r2> "/ad/ sub .*, .*, 0x20;orr .*, .*, 0x8000000000000000"

r2> "/ad/a movk .*, 0xd000, lsl 48"
```

### Frida Script

```js
function swift_string(ptr1, ptr2) {
  const tag = ptr(ptr2).shr(56);
  if (tag == 0x80) {
    // not inlined
    const bias = 0x20;
    const len = Number(ptr(ptr1).shl(8).shr(8));
    const addr = ptr(ptr2).shl(8).shr(8);
    console.log(len);
    const final_addr = addr.add(bias);
    console.log(final_addr);
    return ptr(final_addr).readUtf8String(len);
  } else {
    // inlined
    const len = Number(tag.and(0xf));
    const arr = [];
    for (let i = 0; i < 8; ++i) {
      arr.push(
        Number(
          ptr(ptr1)
            .shr(i * 8)
            .and(0xff),
        ),
      );
    }
    for (let i = 0; i < 7; ++i) {
      arr.push(
        Number(
          ptr(ptr2)
            .shr(i * 8)
            .and(0xff),
        ),
      );
    }
    return String.fromCharCode(...arr.slice(0, len));
  }
}
```

## ABI Calling Convention

- `x20` represents `self` (`__thiscall`)
- `init` and `$init` usually builds object at register x8 then subsequent call to the object method uses `x20` as `this`

```c
pvVar7 = local_478;
// local_478 is loaded at reg x8
SwiftUI::LocalizedStringKey::StringInterpolation::init(local_478,9,1);

SVar11 = Swift::String::init("Current: ",(__int16)local_4e8,1);
// pvVar7 is loaded at reg x20
// SVar11 is loaded at reg x0
SwiftUI::LocalizedStringKey::StringInterpolation::appendLiteral(pvVar7,SVar11,SVar9);

local_270 = Swift::String::init("nilnilnil",9,1);
// local478 is loaded at reg x20
// local_270 is loaded at reg x0
SwiftUI::LocalizedStringKey::StringInterpolation::appendInterpolation(local_478,local_270,SVar9)
```

## SwiftUI Stuff

- `SwiftUI::ViewBuilder::$buildExpression(out_x8, element_x0, type)`: build a single element (intermediate output consumed by `$buildBlock`)
- `SwiftUI::ViewBuilder::$buildBlock(out_x8, element_array_x0, array_count, type_array, vtable_array)`: takes in `TupleView` which is an array of elements (output from `$buildExpression`)
- `SwiftUI::ViewBuilder::$buildBlock(out_x8, element_x0, type, vtable)`

- `SwiftUI::Label::$init`:
  - `x8`: output of `Label`
  - `x0`: title
  - `x2:x3`: image string (maybe?)
  - `x4:x5`: systemImage string

- `SwiftUI::VStack::$init` and `SwiftUI::HStack::$init`:
  - `x8`: output of `VStack` or `HStack`
  - `x2`: closure to build the view inside the `VStack` or `HStack` element

- `SwiftUI::Button::$init`:
  - `x8`: output of `Button`
  - `x0`: action closure
  - `x2`: closure to build the view inside the `Button` element, such as text, label, or image

- `SwiftUI::State::get_wrappedValue`
  - `x20`: state object (`this`)
  - `x8`: out
  - `x0`: state type, e.g., bool, string, etc.

## Appendix

### References

- <https://www.youtube.com/watch?v=2tiC3gjFhew>
