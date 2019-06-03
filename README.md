# kubelogin [![CircleCI](https://circleci.com/gh/int128/kubelogin.svg?style=shield)](https://circleci.com/gh/int128/kubelogin) [![Go Report Card](https://goreportcard.com/badge/github.com/int128/kubelogin)](https://goreportcard.com/report/github.com/int128/kubelogin)

This is a kubectl plugin for [Kubernetes OpenID Connect (OIDC) authentication](https://kubernetes.io/docs/reference/access-authn-authz/authentication/#openid-connect-tokens), also known as `kubectl oidc-login`.
It gets a token from the OIDC provider and writes it to the kubeconfig.


## Getting Started

You can install the latest release from [Homebrew](https://brew.sh/), [Krew](https://github.com/kubernetes-sigs/krew) or [GitHub Releases](https://github.com/int128/kubelogin/releases) as follows:

```sh
# Homebrew
brew tap int128/kubelogin
brew install kubelogin

# Krew
kubectl krew install oidc-login

# GitHub Releases
curl -LO https://github.com/int128/kubelogin/releases/download/v1.11.0/kubelogin_linux_amd64.zip
unzip kubelogin_linux_amd64.zip
ln -s kubelogin kubectl-oidc_login
```

Just run:

```sh
kubelogin
```

It automatically opens the browser and you can log in to the provider.

<img src="docs/keycloak-login.png" alt="keycloak-login" width="455" height="329">

After authentication, an ID token and refresh token will be written to the kubeconfig.

```
% kubelogin
Open http://localhost:8000 for authentication
You got a valid token until 2019-05-18 10:28:51 +0900 JST
Updated ~/.kubeconfig
```

If the token is valid, kubelogin does nothing.

```
% kubelogin
You already have a valid token until 2019-05-18 10:28:51 +0900 JST
```

As well as you can run it as a kubectl plugin:

```sh
kubectl oidc-login
```

For more, see the following documents:

- [Getting Started with Keycloak](docs/keycloak.md)
- [Getting Started with Google Identity Platform](docs/google.md)
- [Team Operation](docs/team_ops.md)


## Configuration

This document is for the development version.
If you are looking for a specific version, see [the release tags](https://github.com/int128/kubelogin/tags).

Kubelogin supports the following options.

```
Options:
      --kubeconfig string              Path to the kubeconfig file
      --context string                 The name of the kubeconfig context to use
      --user string                    The name of the kubeconfig user to use. Prior to --context
      --listen-port ints               Port to bind to the local server. If multiple ports are given, it will try the ports in order (default [8000,18000])
      --skip-open-browser              If true, it does not open the browser on authentication
      --username string                If set, perform the resource owner password credentials grant
      --password string                If set, use the password instead of asking it
      --certificate-authority string   Path to a cert file for the certificate authority
      --insecure-skip-tls-verify       If true, the server's certificate will not be checked for validity. This will make your HTTPS connections insecure
  -v, --v int                          If set to 1 or greater, it shows debug log
```

It supports the following keys of `auth-provider` in a kubeconfig.
See [kubectl authentication](https://kubernetes.io/docs/reference/access-authn-authz/authentication/#using-kubectl) for more.

Key | Direction | Value
----|-----------|------
`idp-issuer-url`                  | Read (Mandatory) | Issuer URL of the provider.
`client-id`                       | Read (Mandatory) | Client ID of the provider.
`client-secret`                   | Read (Mandatory) | Client Secret of the provider.
`idp-certificate-authority`       | Read | CA certificate path of the provider.
`idp-certificate-authority-data`  | Read | Base64 encoded CA certificate of the provider.
`extra-scopes`                    | Read | Scopes to request to the provider (comma separated).
`id-token`                        | Write | ID token got from the provider.
`refresh-token`                   | Write | Refresh token got from the provider.


### Kubeconfig

You can set path to the kubeconfig file by the option or the environment variable just like kubectl.
It defaults to `~/.kube/config`.

```sh
# by the option
kubelogin --kubeconfig /path/to/kubeconfig

# by the environment variable
KUBECONFIG="/path/to/kubeconfig1:/path/to/kubeconfig2" kubelogin
```

If you set multiple files, kubelogin will find the file which has the current authentication (i.e. `user` and `auth-provider`) and write a token to it.


### Authentication flows

#### Authorization code flow

Kubelogin performs the authorization code flow by default.

It starts the local server at port 8000 or 18000 by default.
You need to register the following redirect URIs to the OIDC provider:

- `http://localhost:8000`
- `http://localhost:18000` (used if port 8000 is already in use)

You can change the ports by the option:

```sh
kubelogin --listen-port 12345 --listen-port 23456
```


#### Resource owner password credentials grant flow

You can use the resource owner password credentials grant flow.
Note that not all providers support this flow as:

> The resource owner password credentials grant type is suitable in
> cases where the resource owner has a trust relationship with the
> client, such as the device operating system or a highly privileged
> application.
> The authorization server should take special care when
> enabling this grant type and only allow it when other flows are not
> viable.
>
> <https://tools.ietf.org/html/rfc6749#section-4.3>

You can pass the username and password:

```
% kubelogin --username USER --password PASS
```

or ask the password:

```
% kubelogin --username USER
Password:
```


### Extra scopes

You can set extra scopes to request to the provider by `extra-scopes` in the kubeconfig.

```sh
kubectl config set-credentials keycloak --auth-provider-arg extra-scopes=email
```

Note that kubectl does not accept multiple scopes and you need to edit the kubeconfig as like:

```sh
kubectl config set-credentials keycloak --auth-provider-arg extra-scopes=SCOPES
sed -i '' -e s/SCOPES/email,profile/ $KUBECONFIG
```


### CA Certificates

You can set your self-signed certificates for the OIDC provider (not Kubernetes API server) by kubeconfig or option.

```sh
kubectl config set-credentials keycloak \
  --auth-provider-arg idp-certificate-authority=$HOME/.kube/keycloak-ca.pem
```


### HTTP Proxy

You can set the following environment variables if you are behind a proxy: `HTTP_PROXY`, `HTTPS_PROXY` and `NO_PROXY`.
See also [net/http#ProxyFromEnvironment](https://golang.org/pkg/net/http/#ProxyFromEnvironment).


## Contributions

This is an open source software licensed under Apache License 2.0.

Feel free to open issues and pull requests for improving code and documents.
