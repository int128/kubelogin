# kubelogin [![CircleCI](https://circleci.com/gh/int128/kubelogin.svg?style=shield)](https://circleci.com/gh/int128/kubelogin)

This is a kubectl plugin for [Kubernetes OpenID Connect (OIDC) authentication](https://kubernetes.io/docs/reference/access-authn-authz/authentication/#openid-connect-tokens).
It gets a token from the OIDC provider and writes it to the kubeconfig.


## Getting Started

You need to setup the following components:

- OIDC provider
- Kubernetes API server
- Role for your group or user
- kubectl authentication

You can install [the latest release](https://github.com/int128/kubelogin/releases) by the following ways:

```sh
# Homebrew
brew tap int128/kubelogin
brew install kubelogin

# Krew (experimental)
curl -LO https://github.com/int128/kubelogin/releases/download/v1.9.0/oidc-login.yaml
kubectl krew install --manifest oidc-login.yaml

# GitHub Releases
curl -LO https://github.com/int128/kubelogin/releases/download/v1.9.0/kubelogin_linux_amd64.zip
unzip kubelogin_linux_amd64.zip
ln -s kubelogin kubectl-oidc_login
```

After initial setup or when the token has been expired, just run:

```
% kubelogin
2018/08/27 15:03:06 Reading /home/user/.kube/config
2018/08/27 15:03:06 Using current context: hello.k8s.local
2018/08/27 15:03:07 Open http://localhost:8000 for authorization
2018/08/27 15:03:09 Got token for subject=cf228a73-47fe-4986-a2a8-b2ced80a884b
2018/08/27 15:03:09 Updated /home/user/.kube/config
```

or run as a kubectl plugin:

```
% kubectl oidc-login
```

It opens the browser and you can log in to the provider.
After authentication, it gets an ID token and refresh token and writes them to the kubeconfig.

For more, see the following documents:

- [Getting Started with Keycloak](docs/keycloak.md)
- [Getting Started with Google Identity Platform](docs/google.md)
- [Team Operation](docs/team_ops.md)


## Configuration

This supports the following options.

```
  kubelogin [OPTIONS]

Application Options:
      --kubeconfig=               Path to the kubeconfig file (default: ~/.kube/config) [$KUBECONFIG]
      --listen-port=              Port used by kubelogin to bind its webserver (default: 8000) [$KUBELOGIN_LISTEN_PORT]
      --insecure-skip-tls-verify  If set, the server's certificate will not be checked for validity. This will make your HTTPS connections insecure
                                  [$KUBELOGIN_INSECURE_SKIP_TLS_VERIFY]
      --skip-open-browser         If set, it does not open the browser on authentication. [$KUBELOGIN_SKIP_OPEN_BROWSER]

Help Options:
  -h, --help        Show this help message
```

This also supports the following keys of `auth-provider` in kubeconfig.
See [kubectl authentication](https://kubernetes.io/docs/reference/access-authn-authz/authentication/#using-kubectl).

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


### Kubeconfig path

You can set the environment variable `KUBECONFIG` to point the config file.
Default to `~/.kube/config`.

```sh
export KUBECONFIG="$PWD/.kubeconfig"
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

You can set your self-signed certificates for the OIDC provider (not Kubernetes API server) by `idp-certificate-authority` and `idp-certificate-authority-data` in the kubeconfig.

```sh
kubectl config set-credentials keycloak \
  --auth-provider-arg idp-certificate-authority=$HOME/.kube/keycloak-ca.pem
```

If kubelogin could not parse the certificate, it shows a warning and skips it.


## Contributions

This is an open source software licensed under Apache License 2.0.

Feel free to open issues and pull requests for improving code and documents.
