# CTF Writeups

## pwn

| Challenge Name | CTF Name | Keywords | Summary |
| --- | --- | --- | --- |
| [generic-rop-challenge](./imaginaryctf-2023/pwn/generic-rop-challenge/) | ImaginaryCTF 2023 | aarch64, ARM64, ROP, ret2csu | ret2csu on aarch64 architecture |
| [bofww](./cakectf-2023/pwn/bofww/) | CakeCTF 2023 | bof, cpp | Buffer overflow into arbitrary address write via `std::string` `operator=` |
| [Memorial Cabbage](./cakectf-2023/pwn/memorial-cabbage/) | CakeCTF 2023 | insecure libc function | `mkdtemp` return value lives in the stack instead of heap which allow us to overwrite it |
| [Glacier Rating](./glacierctf-2023/pwn/glacier-rating/) | GlacierCTF 2023 | heap, cpp, tcache poisoning, double free, fastbin dup | Double free into tcache poisoning |
| [Hack The Binary 1](./pwc-hackaday-23/pwn/hack-the-binary-1/) | PwC CTF: Hack A Day 2023 - Securing AI | oob | Array OOB read |
| [Hack The Binary 2](./pwc-hackaday-23/pwn/hack-the-binary-2/) | PwC CTF: Hack A Day 2023 - Securing AI | format string, ROP | Format string to defeat ASLR, ROP to get RCE |

## web

| Challenge Name | CTF Name | Keywords | Summary |
| --- | --- | --- | --- |
| [PHP Code Review 1](./pwc-hackaday-23/web/php-code-review-1/) | PwC CTF: Hack A Day 2023 - Securing AI | php | Leveraging Google search box to capture the flag |
| [PHP Code Review 2](./pwc-hackaday-23/web/php-code-review-2/) | PwC CTF: Hack A Day 2023 - Securing AI | php | Triggerring error to reach `catch` block |
| [Warmup](./wgmy2023/web/warmup/) | Wargames.MY CTF 2023 | php, RCE, LFI | LFI to RCE via PHP PEARCMD |
| [Status](./wgmy2023/web/status/) | Wargames.MY CTF 2023 | php, k8s, nginx, off-by-slash | Retrieve nginx config file from k8s configmaps |
| [Secret](./wgmy2023/web/secret/) | Wargames.MY CTF 2023 | k8s, HashiCorp Vault | Read secret from HashiCorp vault using the `vault` CLI and using `nginx` off-by-slash |
