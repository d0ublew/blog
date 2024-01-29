# CakeCTF 2023

## pwn

| Challenge Name | Keywords | Summary |
| --- | --- | --- |
| [bofww](./pwn/bofww/) | bof, cpp | Buffer overflow into arbitrary address write via `std::string` `operator=` |
| [Memorial Cabbage](./pwn/memorial-cabbage/) | insecure libc function | `mkdtemp` return value lives in the stack instead of heap which allow us to overwrite it |
