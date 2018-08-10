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
2018/08/10 10:36:38 Reading .kubeconfig
2018/08/10 10:36:38 Using current context: devops.hidetake.org
2018/08/10 10:36:41 Open http://localhost:8000 for authorization
2018/08/10 10:36:45 GET /
2018/08/10 10:37:07 GET /?state=...&session_state=...&code=ey...
2018/08/10 10:37:08 Updated .kubeconfig
```

Now your `~/.kube/config` looks like:

```yaml
# ~/.kube/config (snip)
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
- Allowed redirect URLs: `http://localhost:8000/`
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

In actual team operation, you can share the following config to your team members for easy setup.

```yaml
#!/bin/sh
CLUSTER_NAME="hello.k8s.local"

# Set the certificate
mkdir -p "$HOME/.kube"
cat > "$HOME/.kube/$CLUSTER_NAME.crt" <<EOF
-----BEGIN CERTIFICATE-----
MII...
-----END CERTIFICATE-----
EOF

# Set the cluster
kubectl config set-cluster "$CLUSTER_NAME" \
  --server https://api-xxx.xxx.elb.amazonaws.com \
  --certificate-authority "$HOME/.kube/$CLUSTER_NAME.crt"

# Set the credentials
kubectl config set-credentials "$CLUSTER_NAME" \
  --auth-provider oidc \
  --auth-provider-arg idp-issuer-url=https://keycloak.example.com/auth/realms/hello \
  --auth-provider-arg client-id=kubernetes \
  --auth-provider-arg client-secret=YOUR_SECRET

# Set the context
kubectl config set-context "$CLUSTER_NAME" --cluster "$CLUSTER_NAME" --user "$CLUSTER_NAME"

# Set the current context
kubectl config use-context "$CLUSTER_NAME"
```


## Contributions

This is an open source software licensed under Apache License 2.0.
Feel free to open issues and pull requests.

### Build

```sh
go get github.com/int128/kubelogin
```

### Release

CircleCI publishes the build to GitHub. See [.circleci/config.yml](.circleci/config.yml).
