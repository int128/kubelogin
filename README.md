# kubelogin [![CircleCI](https://circleci.com/gh/int128/kubelogin.svg?style=shield)](https://circleci.com/gh/int128/kubelogin)

`kubelogin` is a command to get an OpenID Connect (OIDC) token for `kubectl` authentication.


## Getting Started

Download [the latest release](https://github.com/int128/kubelogin/releases) and save it as `/usr/local/bin/kubelogin`.

You have to configure `kubectl` to authenticate with OIDC.
See the later section for details.

```sh
kubectl config set-credentials CLUSTER_NAME \
  --auth-provider oidc \
  --auth-provider-arg idp-issuer-url=https://keycloak.example.com/auth/realms/hello \
  --auth-provider-arg client-id=kubernetes \
  --auth-provider-arg client-secret=YOUR_CLIENT_SECRET
```

Run `kubelogin`.

```
% kubelogin
2018/03/23 18:01:40 Reading config from /home/user/.kube/config
2018/03/23 18:01:40 Using current context: hello.k8s.local
2018/03/23 18:01:40 Using issuer: https://keycloak.example.com/auth/realms/hello
2018/03/23 18:01:40 Using client ID: kubernetes
2018/03/23 18:01:41 Starting OpenID Connect authentication:

## Automatic (recommended)

Open the following URL in the web browser:

http://localhost:8000/

## Manual

If you cannot access to localhost, instead open the following URL:

https://keycloak.example.com/auth/realms/hello/protocol/openid-connect/auth?client_id=kubernetes&redirect_uri=urn%3Aietf%3Awg%3Aoauth%3A2.0%3Aoob&response_type=code&scope=openid+email&state=********

Enter the code:
```

Open http://localhost:8000 in your browser.
If you cannot access to localhost, you can get the authorization code and enter it manually instead.

Then, `kubelogin` will update your `~/.kube/config` with the ID token and refresh token.

```
2018/03/23 18:01:46 Exchanging code and token...
2018/03/23 18:01:46 Verifying ID token...
2018/03/23 18:01:46 You are logged in as foo@example.com (********)
2018/03/23 18:01:46 Updated /home/user/.kube/config
```

Your `~/.kube/config` looks like:

```yaml
# ~/.kube/config (snip)
current-context: hello.k8s.local
contexts:
- context:
    cluster: hello.k8s.local
    user: hello.k8s.local
  name: hello.k8s.local
users:
- name: hello.k8s.local
  user:
    auth-provider:
      config:
        idp-issuer-url: https://keycloak.example.com/auth/realms/hello
        client-id: kubernetes
        client-secret: YOUR_SECRET
        id-token: ey...       # kubelogin will update ID token here
        refresh-token: ey...  # kubelogin will update refresh token here
      name: oidc
```

Make sure you can access to the Kubernetes cluster:

```
% kubectl version
Client Version: version.Info{...}
Server Version: version.Info{...}
```


## Configuration

You can set the following environment variable:

- `KUBECONFIG` - Path to the config. Defaults to `~/.kube/config`.


## Prerequisite

You have to setup your OIDC identity provider and Kubernetes cluster.

### 1. Setup OIDC Identity Provider

This tutorial assumes you have created an OIDC client with the following:

- Issuer URL: `https://keycloak.example.com/auth/realms/hello`
- Client ID: `kubernetes`
- Client Secret: `YOUR_CLIENT_SECRET`
- Allowed redirect URLs:
  - `http://localhost:8000/`
  - `urn:ietf:wg:oauth:2.0:oob`
- Groups claim: `groups` (optional for group based access controll)

### 2. Setup Kubernetes API Server

Configure the Kubernetes API server allows your identity provider.

If you are using [kops](https://github.com/kubernetes/kops), `kops edit cluster` and append the following settings:

```yaml
spec:
  kubeAPIServer:
    oidcClientID: kubernetes
    oidcGroupsClaim: groups
    oidcIssuerURL: https://keycloak.example.com/auth/realms/hello
```

### 3. Setup kubectl

Run the following command to configure `kubectl` to authenticate by your identity provider.

```sh
kubectl config set-credentials CLUSTER_NAME \
  --auth-provider oidc \
  --auth-provider-arg idp-issuer-url=https://keycloak.example.com/auth/realms/hello \
  --auth-provider-arg client-id=kubernetes \
  --auth-provider-arg client-secret=YOUR_CLIENT_SECRET
```

In actual team operation, you can share the following script to your team members for easy setup.

```sh
CLUSTER_NAME="hello.k8s.local"

# Set the certificate
echo "YOUR_CERTIFICATE" > "~/.kube/$CLUSTER_NAME.crt"

# Set the cluster
kubectl config set-cluster "$CLUSTER_NAME" \
  --server https://api-xxx.elb.amazonaws.com \
  --certificate-authority "~/.kube/$CLUSTER_NAME.crt"

# Set the credentials
kubectl config set-credentials "$CLUSTER_NAME" \
  --auth-provider oidc \
  --auth-provider-arg idp-issuer-url=https://keycloak.example.com/auth/realms/hello \
  --auth-provider-arg client-id=kubernetes \
  --auth-provider-arg client-secret=YOUR_CLIENT_SECRET

# Set the context
kubectl config set-context "$CLUSTER_NAME" --cluster "$CLUSTER_NAME" --user "$CLUSTER_NAME"
```


## Contributions

This is an open source software licensed under Apache License 2.0.
Feel free to open issues and pull requests.

### How to build

```sh
go get github.com/int128/kubelogin
```
