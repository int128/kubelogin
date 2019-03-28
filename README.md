# kubelogin [![CircleCI](https://circleci.com/gh/int128/kubelogin.svg?style=shield)](https://circleci.com/gh/int128/kubelogin)

This is a kubectl plugin for [Kubernetes OpenID Connect (OIDC) authentication](https://kubernetes.io/docs/reference/access-authn-authz/authentication/#openid-connect-tokens).
It gets a token from the OIDC provider and writes it to the kubeconfig.


## TL;DR

You need to setup the following components:

- OIDC provider
- Kubernetes API server
- Role for your group or user
- kubectl authentication

You can install this by brew tap or from the [releases](https://github.com/int128/kubelogin/releases).

```sh
brew tap int128/kubelogin
brew install kubelogin
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
Usage: kubelogin [options]

Options:
      --listen-port int                Port used by kubelogin to bind its server [$KUBELOGIN_LISTEN_PORT] (default 8000)
      --skip-open-browser              If true, it does not open the browser on authentication [$KUBELOGIN_SKIP_OPEN_BROWSER]
      --kubeconfig string              Path to the kubeconfig file to use for CLI requests. [$KUBECONFIG]
      --cache-dir string               Default HTTP cache directory (default "~/.kube/http-cache")
      --client-certificate string      Path to a client certificate file for TLS
      --client-key string              Path to a client key file for TLS
      --token string                   Bearer token for authentication to the API server
      --as string                      Username to impersonate for the operation
      --as-group stringArray           Group to impersonate for the operation, this flag can be repeated to specify multiple groups.
      --cluster string                 The name of the kubeconfig cluster to use
      --user string                    The name of the kubeconfig user to use
  -n, --namespace string               If present, the namespace scope for this CLI request
      --context string                 The name of the kubeconfig context to use
  -s, --server string                  The address and port of the Kubernetes API server
      --insecure-skip-tls-verify       If true, the server's certificate will not be checked for validity. This will make your HTTPS connections insecure [$KUBELOGIN_INSECURE_SKIP_TLS_VERIFY]
      --certificate-authority string   Path to a cert file for the certificate authority
      --request-timeout string         The length of time to wait before giving up on a single server request. Non-zero values should contain a corresponding time unit (e.g. 1s, 2m, 3h). A value of zero means don't timeout requests. (default "0")
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
