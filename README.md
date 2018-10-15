# kubelogin [![CircleCI](https://circleci.com/gh/int128/kubelogin.svg?style=shield)](https://circleci.com/gh/int128/kubelogin)

This is a command for [Kubernetes OpenID Connect (OIDC) authentication](https://kubernetes.io/docs/reference/access-authn-authz/authentication/#openid-connect-tokens).
It gets a token from the OIDC provider and writes it to the kubeconfig.


## TL;DR

You need to setup the following components:

- OIDC provider
- Kubernetes API server
- Kubernetes cluster (RBAC)
- kubectl

You can install this by brew tap or from the [releases](https://github.com/int128/kubelogin/releases).

```sh
brew tap int128/kubelogin
brew install kubelogin
```

After initial setup or when the token has been expired, just run `kubelogin`.

```
% kubelogin
2018/08/27 15:03:06 Reading /home/user/.kube/config
2018/08/27 15:03:06 Using current context: hello.k8s.local
2018/08/27 15:03:07 Open http://localhost:8000 for authorization
2018/08/27 15:03:07 GET /
2018/08/27 15:03:08 GET /?state=a51081925f20c043&session_state=5637cbdf-ffdc-4fab-9fc7-68a3e6f2e73f&code=ey...
2018/08/27 15:03:09 Got token for subject=cf228a73-47fe-4986-a2a8-b2ced80a884b
2018/08/27 15:03:09 Updated /home/user/.kube/config
```

It will open the browser and you can log in to the provider.
And then it gets the ID token and refresh token and writes them to the kubeconfig.

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
`idp-issuer-url`                  | IN (Required) | Issuer URL of the provider.
`client-id`                       | IN (Required) | Client ID of the provider.
`client-secret`                   | IN (Required) | Client Secret of the provider.
`idp-certificate-authority`       | IN (Optional) | CA certificate path of the provider.
`idp-certificate-authority-data`  | IN (Optional) | Base64 encoded CA certificate of the provider.
`extra-scopes`                    | IN (Optional) | Scopes to request to the provider (comma separated).
`id-token`                        | OUT | ID token got from the provider.
`refresh-token`                   | OUT | Refresh token got from the provider.


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

Note that kubectl does not accept multiple scopes and you need to edit the kubeconfig.

```sh
kubectl config set-credentials keycloak --auth-provider-arg extra-scopes=SCOPES
sed -i '' -e s/SCOPES/email,profile/ $KUBECONFIG
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

CircleCI publishes the build to GitHub.
See [.circleci/config.yml](.circleci/config.yml).
