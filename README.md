# kubelogin [![CircleCI](https://circleci.com/gh/int128/kubelogin.svg?style=shield)](https://circleci.com/gh/int128/kubelogin)

This is a helper command for [Kubernetes OpenID Connect (OIDC) authentication](https://kubernetes.io/docs/reference/access-authn-authz/authentication/#openid-connect-tokens).
It gets a token from the OIDC provider and writes it to the kubeconfig.

This may work with various OIDC providers such as Keycloak, Google Identity Platform and Azure AD.


## TL;DR

You need to setup the OIDC provider and [Kubernetes OIDC authentication](https://kubernetes.io/docs/reference/access-authn-authz/authentication/#openid-connect-tokens).

After setup or when the token has been expired, just run `kubelogin`:

```
% kubelogin
2018/08/27 15:03:06 Reading /home/user/.kube/config
2018/08/27 15:03:06 Using current context: hello.k8s.local
2018/08/27 15:03:07 Open http://localhost:8000 for authorization
```

It opens the browser and you can log in to the provider.
After you logged in to the provider, it closes the browser automatically.

Then it writes the ID token and refresh token to the kubeconfig.

```
2018/08/27 15:03:07 GET /
2018/08/27 15:03:08 GET /?state=a51081925f20c043&session_state=5637cbdf-ffdc-4fab-9fc7-68a3e6f2e73f&code=ey...
2018/08/27 15:03:09 Got token for subject=cf228a73-47fe-4986-a2a8-b2ced80a884b
2018/08/27 15:03:09 Updated /home/user/.kube/config
```

Please see the later section for details.


## Getting Started with Google Account

### 1. Setup Google API

Open [Google APIs Console](https://console.developers.google.com/apis/credentials) and create an OAuth client as follows:

- Application Type: Web application
- Redirect URL: `http://localhost:8000/`

### 2. Setup Kubernetes cluster

Configure your Kubernetes API Server accepts [OpenID Connect Tokens](https://kubernetes.io/docs/reference/access-authn-authz/authentication/#openid-connect-tokens).
If you are using [kops](https://github.com/kubernetes/kops), run `kops edit cluster` and append the following settings:

```yaml
spec:
  kubeAPIServer:
    oidcIssuerURL: https://accounts.google.com
    oidcClientID: YOUR_CLIENT_ID.apps.googleusercontent.com
```

Here assign the `cluster-admin` role to your user.

```yaml
kind: ClusterRoleBinding
apiVersion: rbac.authorization.k8s.io/v1
metadata:
  name: oidc-admin-group
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: cluster-admin
subjects:
- kind: User
  name: https://accounts.google.com#1234567890
```

### 3. Setup kubectl and kubelogin

Setup `kubectl` to authenticate with your identity provider.

```sh
kubectl config set-credentials CLUSTER_NAME \
  --auth-provider oidc \
  --auth-provider-arg idp-issuer-url=https://accounts.google.com \
  --auth-provider-arg client-id=YOUR_CLIENT_ID.apps.googleusercontent.com \
  --auth-provider-arg client-secret=YOUR_CLIENT_SECRET
```

Download [the latest release](https://github.com/int128/kubelogin/releases) and save it.

Run `kubelogin` and open http://localhost:8000 in your browser.

```
% kubelogin
2018/08/10 10:36:38 Reading .kubeconfig
2018/08/10 10:36:38 Using current context: hello.k8s.local
2018/08/10 10:36:41 Open http://localhost:8000 for authorization
2018/08/10 10:36:45 GET /
2018/08/10 10:37:07 GET /?state=...&session_state=...&code=ey...
2018/08/10 10:37:08 Updated .kubeconfig
```

Now your `~/.kube/config` should be like:

```yaml
users:
- name: hello.k8s.local
  user:
    auth-provider:
      config:
        idp-issuer-url: https://accounts.google.com
        client-id: YOUR_CLIENT_ID.apps.googleusercontent.com
        client-secret: YOUR_SECRET
        id-token: ey...       # kubelogin will update ID token here
        refresh-token: ey...  # kubelogin will update refresh token here
      name: oidc
```

Make sure you can access to the Kubernetes cluster.

```
% kubectl get nodes
NAME                                    STATUS    ROLES     AGE       VERSION
ip-1-2-3-4.us-west-2.compute.internal   Ready     node      21d       v1.9.6
ip-1-2-3-5.us-west-2.compute.internal   Ready     node      20d       v1.9.6
```


## Getting Started with Keycloak

### 1. Setup Keycloak

Create an OIDC client as follows:

- Redirect URL: `http://localhost:8000/`
- Issuer URL: `https://keycloak.example.com/auth/realms/YOUR_REALM`
- Client ID: `kubernetes`
- Groups claim: `groups`

Then create a group `kubernetes:admin` and join to it.

### 2. Setup Kubernetes cluster

Configure your Kubernetes API Server accepts [OpenID Connect Tokens](https://kubernetes.io/docs/reference/access-authn-authz/authentication/#openid-connect-tokens).
If you are using [kops](https://github.com/kubernetes/kops), run `kops edit cluster` and append the following settings:

```yaml
spec:
  kubeAPIServer:
    oidcIssuerURL: https://keycloak.example.com/auth/realms/YOUR_REALM
    oidcClientID: kubernetes
    oidcGroupsClaim: groups
```

Here assign the `cluster-admin` role to the `kubernetes:admin` group.

```yaml
kind: ClusterRoleBinding
apiVersion: rbac.authorization.k8s.io/v1
metadata:
  name: keycloak-admin-group
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: cluster-admin
subjects:
- kind: Group
  name: /kubernetes:admin
```

### 3. Setup kubectl and kubelogin

Setup `kubectl` to authenticate with your identity provider.

```sh
kubectl config set-credentials CLUSTER_NAME \
  --auth-provider oidc \
  --auth-provider-arg idp-issuer-url=https://keycloak.example.com/auth/realms/YOUR_REALM \
  --auth-provider-arg client-id=kubernetes \
  --auth-provider-arg client-secret=YOUR_CLIENT_SECRET
```

Download [the latest release](https://github.com/int128/kubelogin/releases) and save it.

Run `kubelogin` and make sure you can access to the cluster.
See the previous section for details.


## Configuration

```
  kubelogin [OPTIONS]

Application Options:
      --kubeconfig=               Path to the kubeconfig file (default: ~/.kube/config) [$KUBECONFIG]
      --insecure-skip-tls-verify  If set, the server's certificate will not be checked for validity. This will make your HTTPS connections insecure
                                  [$KUBELOGIN_INSECURE_SKIP_TLS_VERIFY]
      --skip-open-browser         If set, it does not open the browser on authentication. [$KUBELOGIN_SKIP_OPEN_BROWSER]

Help Options:
  -h, --help        Show this help message
```

This supports the following `auth-provider` keys in kubeconfig.
See also [kubectl authentication](https://kubernetes.io/docs/reference/access-authn-authz/authentication/#using-kubectl).

Key | Direction | Value
----|-----------|------
`idp-issuer-url`                  | IN (Required) | Issuer URL of the provider.
`client-id`                       | IN (Required) | Client ID of the provider.
`client-secret`                   | IN (Required) | Client Secret of the provider.
`idp-certificate-authority`       | IN (Optional) | CA certificate path of the provider.
`idp-certificate-authority-data`  | IN (Optional) | Base64 encoded CA certificate of the provider.
`id-token`                        | OUT | ID token got from the provider.
`refresh-token`                   | OUT | Refresh token got from the provider.


### Kubeconfig path

You can set the environment variable `KUBECONFIG` to point the config file.
Default to `~/.kube/config`.

```sh
export KUBECONFIG="$PWD/.kubeconfig"
```

### Team onboarding

You can share the kubeconfig to your team members for easy setup.

```yaml
apiVersion: v1
kind: Config
clusters:
  - cluster:
      certificate-authority-data: LS...
      server: https://api.hello.k8s.example.com
      name: hello.k8s.local
contexts:
- context:
    cluster: hello.k8s.local
    user: hello.k8s.local
  name: hello.k8s.local
current-context: hello.k8s.local
preferences: {}
users:
- name: hello.k8s.local
  user:
    auth-provider:
      name: oidc
      config:
        client-id: YOUR_CLIEND_ID
        client-secret: YOUR_CLIENT_SECRET
        idp-issuer-url: YOUR_ISSUER
```

If you are using kops, export the kubeconfig and edit it.

```sh
KUBECONFIG=.kubeconfig kops export kubecfg hello.k8s.local
vim .kubeconfig
```


## Contributions

This is an open source software licensed under Apache License 2.0.
Feel free to open issues and pull requests.

### Build and Test

```sh
go get github.com/int128/kubelogin
```

```sh
cd $GOPATH/src/github.com/int128/kubelogin
make -C e2e/authserver/testdata
go test -v ./...
```

### Release

CircleCI publishes the build to GitHub. See [.circleci/config.yml](.circleci/config.yml).
