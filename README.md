# kubelogin [![CircleCI](https://circleci.com/gh/int128/kubelogin.svg?style=shield)](https://circleci.com/gh/int128/kubelogin) [![Go Report Card](https://goreportcard.com/badge/github.com/int128/kubelogin)](https://goreportcard.com/report/github.com/int128/kubelogin)

This is a kubectl plugin for [Kubernetes OpenID Connect (OIDC) authentication](https://kubernetes.io/docs/reference/access-authn-authz/authentication/#openid-connect-tokens), also known as `kubectl oidc-login`.

This is designed to run as a [client-go credential plugin](https://kubernetes.io/docs/reference/access-authn-authz/authentication/#client-go-credential-plugins).
When you run kubectl, kubelogin opens the browser and you can log in to the provider.
Then kubelogin gets a token from the provider and kubectl access Kubernetes APIs with the token.


## Getting Started

You can install the latest release from [Homebrew](https://brew.sh/), [Krew](https://github.com/kubernetes-sigs/krew) or [GitHub Releases](https://github.com/int128/kubelogin/releases) as follows:

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

You need to configure the OIDC provider, Kubernetes API server, kubeconfig and role binding.
See the following documents for more:

- [Getting Started with Keycloak](docs/keycloak.md)
- [Getting Started with dex and GitHub](docs/dex.md)
- [Getting Started with Google Identity Platform](docs/google.md)

You can run kubelogin as the following methods:

- Credential plugin mode (recommended)
- Standalone mode


### Credential plugin mode

You can run kubelogin as a [client-go credential plugin](https://kubernetes.io/docs/reference/access-authn-authz/authentication/#client-go-credential-plugins).
This provides transparent login without manually running `kubelogin` command.

Configure the kubeconfig like:

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

You can run kubelogin as a standalone command.
In this method, you need to manually run the command before running kubectl.

Configure the kubeconfig like:

```yaml
- name: keycloak
  user:
    auth-provider:
      config:
        client-id: YOUR_CLIENT_ID
        client-secret: YOUR_CLIENT_SECRET
        idp-issuer-url: https://issuer.example.com
      name: oidc
```

Run kubelogin:

```sh
kubelogin

# or run as a kubectl plugin
kubectl oidc-login
```

It automatically opens the browser and you can log in to the provider.

<img src="docs/keycloak-login.png" alt="keycloak-login" width="455" height="329">

After authentication, kubelogin writes the ID token and refresh token to the kubeconfig.

```
% kubelogin
Open http://localhost:8000 for authentication
You got a valid token until 2019-05-18 10:28:51 +0900 JST
Updated ~/.kubeconfig
```

Now you can access the cluster.

```
% kubectl get pods
NAME                          READY   STATUS    RESTARTS   AGE
echoserver-86c78fdccd-nzmd5   1/1     Running   0          26d
```

Your kubeconfig looks like:

```yaml
users:
- name: keycloak
  user:
    auth-provider:
      config:
        client-id: YOUR_CLIENT_ID
        client-secret: YOUR_CLIENT_SECRET
        idp-issuer-url: https://issuer.example.com
        id-token: ey...       # kubelogin will add or update the ID token here
        refresh-token: ey...  # kubelogin will add or update the refresh token here
      name: oidc
```

If the ID token is valid, kubelogin does nothing.

```
% kubelogin
You already have a valid token until 2019-05-18 10:28:51 +0900 JST
```

If the ID token has expired, kubelogin will refresh the token using the refresh token in the kubeconfig.
If the refresh token has expired, kubelogin will proceed the authentication.


## Configuration

This document is for the development version.
If you are looking for a specific version, see [the release tags](https://github.com/int128/kubelogin/tags).


### Credential plugin mode

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

#### Extra scopes

You can set the extra scopes to request to the provider by `--oidc-extra-scope`.

```yaml
      - --oidc-extra-scope=email
      - --oidc-extra-scope=profile
```

#### CA Certificates

You can use your self-signed certificates for the provider.

```yaml
      - --certificate-authority=/home/user/.kube/keycloak-ca.pem
```


### Standalone mode

Kubelogin supports the following options:

```
% kubelogin -h
Login to the OpenID Connect provider and update the kubeconfig

Usage:
  kubelogin [flags]
  kubelogin [command]

Examples:
  # Login to the provider using the authorization code flow.
  kubelogin

  # Login to the provider using the resource owner password credentials flow.
  kubelogin --username USERNAME --password PASSWORD

  # Run as a credential plugin.
  kubelogin get-token --oidc-issuer-url=https://issuer.example.com

Available Commands:
  get-token   Run as a kubectl credential plugin
  help        Help about any command
  version     Print the version information

Flags:
      --kubeconfig string              Path to the kubeconfig file
      --context string                 The name of the kubeconfig context to use
      --user string                    The name of the kubeconfig user to use. Prior to --context
      --certificate-authority string   Path to a cert file for the certificate authority
      --insecure-skip-tls-verify       If true, the server's certificate will not be checked for validity. This will make your HTTPS connections insecure
  -v, --v int                          If set to 1 or greater, it shows debug log
      --listen-port ints               Port to bind to the local server. If multiple ports are given, it will try the ports in order (default [8000,18000])
      --skip-open-browser              If true, it does not open the browser on authentication
      --username string                If set, perform the resource owner password credentials grant
      --password string                If set, use the password instead of asking it
  -h, --help                           help for kubelogin
```

#### Kubeconfig

You can set path to the kubeconfig file by the option or the environment variable just like kubectl.
It defaults to `~/.kube/config`.

```sh
# by the option
kubelogin --kubeconfig /path/to/kubeconfig

# by the environment variable
KUBECONFIG="/path/to/kubeconfig1:/path/to/kubeconfig2" kubelogin
```

If you set multiple files, kubelogin will find the file which has the current authentication (i.e. `user` and `auth-provider`) and write a token to it.

Kubelogin supports the following keys of `auth-provider` in a kubeconfig.
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

#### Extra scopes

You can set the extra scopes to request to the provider by `extra-scopes` in the kubeconfig.

```sh
kubectl config set-credentials keycloak --auth-provider-arg extra-scopes=email
```

Currently kubectl does not accept multiple scopes, so you need to edit the kubeconfig as like:

```sh
kubectl config set-credentials keycloak --auth-provider-arg extra-scopes=SCOPES
sed -i '' -e s/SCOPES/email,profile/ $KUBECONFIG
```

#### CA Certificates

You can use your self-signed certificates for the provider.

```sh
kubectl config set-credentials keycloak \
  --auth-provider-arg idp-certificate-authority=$HOME/.kube/keycloak-ca.pem
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

```sh
# run as a standalone command
kubelogin --listen-port 12345 --listen-port 23456

# run as a credential plugin
kubelogin get-token --listen-port 12345 --listen-port 23456
```


#### Resource owner password credentials grant flow

As well as you can use the resource owner password credentials grant flow.
Keycloak supports this flow but you need to explicitly enable the "Direct Access Grants" feature in the client settings.
Most OIDC providers do not support this flow.

You can pass the username and password:

```
% kubelogin --username USER --password PASS
```

or use the password prompt:

```
% kubelogin --username USER
Password:
```


## Related topics

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
