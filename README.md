# kubelogin [![CircleCI](https://circleci.com/gh/int128/kubelogin.svg?style=shield)](https://circleci.com/gh/int128/kubelogin) [![Go Report Card](https://goreportcard.com/badge/github.com/int128/kubelogin)](https://goreportcard.com/report/github.com/int128/kubelogin)

This is a kubectl plugin for [Kubernetes OpenID Connect (OIDC) authentication](https://kubernetes.io/docs/reference/access-authn-authz/authentication/#openid-connect-tokens), also known as `kubectl oidc-login`.

This is designed to run as a [client-go credential plugin](https://kubernetes.io/docs/reference/access-authn-authz/authentication/#client-go-credential-plugins).
When you run kubectl, kubelogin opens the browser and you can log in to the provider.
Then kubelogin gets a token from the provider and kubectl access Kubernetes APIs with the token.


## Getting Started

### Setup

Install the latest release from [Homebrew](https://brew.sh/), [Krew](https://github.com/kubernetes-sigs/krew) or [GitHub Releases](https://github.com/int128/kubelogin/releases) as follows:

```sh
# Homebrew
brew install int128/kubelogin/kubelogin

# Krew
kubectl krew install oidc-login

# GitHub Releases
curl -LO https://github.com/int128/kubelogin/releases/download/v1.14.2/kubelogin_linux_amd64.zip
unzip kubelogin_linux_amd64.zip
ln -s kubelogin kubectl-oidc_login
```

You need to configure the OIDC provider, Kubernetes API server and role binding.
See the following documents for more:

- [Getting Started with Keycloak](docs/keycloak.md)
- [Getting Started with dex and GitHub](docs/dex.md)
- [Getting Started with Google Identity Platform](docs/google.md)

Configure the kubeconfig to run kubelogin as a [client-go credential plugin](https://kubernetes.io/docs/reference/access-authn-authz/authentication/#client-go-credential-plugins).
It provides transparent login without manually running kubelogin command.
For example,

```yaml
users:
- name: keycloak
  user:
    exec:
      apiVersion: client.authentication.k8s.io/v1beta1
      command: kubectl
      args:
      - oidc-login
      - get-token
      - --oidc-issuer-url=https://issuer.example.com
      - --oidc-client-id=YOUR_CLIENT_ID
      - --oidc-client-secret=YOUR_CLIENT_SECRET
```

### Run

Run kubectl.

```sh
kubectl get pods
```

Kubectl executes kubelogin before calling the Kubernetes APIs.
Kubelogin automatically opens the browser and you can log in to the provider.

<img src="docs/keycloak-login.png" alt="keycloak-login" width="455" height="329">

After authentication, kubelogin returns the credentials to kubectl and finally kubectl calls the Kubernetes APIs with the credential.

```
% kubectl get pods
Open http://localhost:8000 for authentication
You got a valid token until 2019-05-18 10:28:51 +0900 JST
NAME                          READY   STATUS    RESTARTS   AGE
echoserver-86c78fdccd-nzmd5   1/1     Running   0          26d
```

Kubelogin writes the ID token and refresh token to the token cache file.

If the cached ID token is valid, kubelogin just returns it.
If the cached ID token has expired, kubelogin will refresh the token using the refresh token.
If the refresh token has expired, kubelogin will perform reauthentication.

You can log out by removing the token cache directory (default `~/.kube/cache/oidc-login`).
Kubelogin will perform authentication if the token cache file does not exist.

### Standalone mode

As well as you can update the ID token in the kubeconfig by running the command.
See [standalone mode](docs/standalone-mode.md) for more.


## Usage

This document is for the development version.
If you are looking for a specific version, see [the release tags](https://github.com/int128/kubelogin/tags).

Kubelogin supports the following options:

```
% kubelogin get-token -h
Run as a kubectl credential plugin

Usage:
  kubelogin get-token [flags]

Flags:
      --listen-port ints               Port to bind to the local server. If multiple ports are given, it will try the ports in order (default [8000,18000])
      --skip-open-browser              If true, it does not open the browser on authentication
      --username string                If set, perform the resource owner password credentials grant
      --password string                If set, use the password instead of asking it
      --oidc-issuer-url string         Issuer URL of the provider (mandatory)
      --oidc-client-id string          Client ID of the provider (mandatory)
      --oidc-client-secret string      Client secret of the provider
      --oidc-extra-scope strings       Scopes to request to the provider
      --certificate-authority string   Path to a cert file for the certificate authority
      --insecure-skip-tls-verify       If true, the server's certificate will not be checked for validity. This will make your HTTPS connections insecure
  -v, --v int                          If set to 1 or greater, it shows debug log
      --token-cache-dir string         Path to a directory for caching tokens (default "~/.kube/cache/oidc-login")
  -h, --help                           help for get-token
```

See also the options in [standalone mode](docs/standalone-mode.md).

### Extra scopes

You can set the extra scopes to request to the provider by `--oidc-extra-scope`.

```yaml
      - --oidc-extra-scope=email
      - --oidc-extra-scope=profile
```

### CA Certificates

You can use your self-signed certificate for the provider.

```yaml
      - --certificate-authority=/home/user/.kube/keycloak-ca.pem
```

### HTTP Proxy

You can set the following environment variables if you are behind a proxy: `HTTP_PROXY`, `HTTPS_PROXY` and `NO_PROXY`.
See also [net/http#ProxyFromEnvironment](https://golang.org/pkg/net/http/#ProxyFromEnvironment).


### Authentication flows

#### Authorization code flow

Kubelogin performs the authorization code flow by default.

It starts the local server at port 8000 or 18000 by default.
You need to register the following redirect URIs to the provider:

- `http://localhost:8000`
- `http://localhost:18000` (used if port 8000 is already in use)

You can change the ports by the option:

```yaml
      - --listen-port 12345
      - --listen-port 23456
```

#### Resource owner password credentials grant flow

As well as you can use the resource owner password credentials grant flow.
Keycloak supports this flow but you need to explicitly enable the "Direct Access Grants" feature in the client settings.
Most OIDC providers do not support this flow.

You can pass the username and password:

```yaml
      - --username USERNAME
      - --password PASSWORD
```

If the password is not set, kubelogin will show the prompt.

```
% kubelogin --username USER
Password:
```


## Related works

### Kubernetes Dashboard

You can access the Kubernetes Dashboard using kubelogin and [kauthproxy](https://github.com/int128/kauthproxy).


## Contributions

This is an open source software licensed under Apache License 2.0.
Feel free to open issues and pull requests for improving code and documents.

### Development

Go 1.12 or later is required.

```sh
# Run lint and tests
make check

# Compile and run the command
make
./kubelogin
```
