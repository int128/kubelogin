# kubelogin [![CircleCI](https://circleci.com/gh/int128/kubelogin.svg?style=shield)](https://circleci.com/gh/int128/kubelogin)

`kubelogin` is a command to setup OpenID Connect (OIDC) authentication for `kubectl`.

## Getting Started

### 1. Setup OIDC Identity Provider

This article assumes you have created an OIDC client with the following:

- Issuer URL: `https://keycloak.example.com/auth/realms/hello`
- Redirect URL: `https://kubernetes-dashboard.example.com/*`
- Client ID: `kubernetes`
- Client Secret: `YOUR_CLIENT_SECRET`
- Groups claim: `groups` (optional for group based access controll)

### 2. Setup Kubernetes API Server

Setup the Kubernetes API server allows your identity provider.

If you are using kops, `kops edit cluster` and append the following settings:

```yaml
spec:
  kubeAPIServer:
    oidcClientID: kubernetes
    oidcGroupsClaim: groups
    oidcIssuerURL: https://keycloak.example.com/auth/realms/hello
```

### 3. Setup kubectl

Share the following script to setup `kubectl`:

```sh
CLUSTER_NAME=hello.k8s.local

# Set the cluster
kubectl config set-cluster $CLUSTER_NAME \
  --server https://api.example.com \
  --certificate-authority ~/.kube/$CLUSTER_NAME.crt

# Set the credentials
kubectl config set-credentials $CLUSTER_NAME \
  --auth-provider oidc \
  --auth-provider-arg idp-issuer-url=https://keycloak.example.com/auth/realms/hello \
  --auth-provider-arg client-id=kubernetes \
  --auth-provider-arg client-secret=YOUR_CLIENT_SECRET

# Set the context
kubectl config set-context $CLUSTER_NAME --cluster $CLUSTER_NAME --user $CLUSTER_NAME
```

### 4. Use kubelogin and kubectl

Refresh the ID token:

```
% kubelogin
2018/03/21 17:13:20 Reading config from ~/.kube/config
---- Authentication ----
1. Open the following URL:

https://keycloak.example.com/auth/realms/hello/protocol/openid-connect/auth?client_id=...

2. Enter the code: ey...

2018/03/21 17:13:32 Updated ~/.kube/config
```

Make sure you can access to the cluster:

```
% kubectl version
Client Version: version.Info{...}
Server Version: version.Info{...}
```
