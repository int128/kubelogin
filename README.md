# kubelogin [![go](https://github.com/int128/kubelogin/actions/workflows/go.yaml/badge.svg)](https://github.com/int128/kubelogin/actions/workflows/go.yaml) [![Go Report Card](https://goreportcard.com/badge/github.com/int128/kubelogin)](https://goreportcard.com/report/github.com/int128/kubelogin)

This is a kubectl plugin for [Kubernetes OpenID Connect (OIDC) authentication](https://kubernetes.io/docs/reference/access-authn-authz/authentication/#openid-connect-tokens), also known as `kubectl oidc-login`.

Here is an example of Kubernetes authentication with the Google Identity Platform:

<img alt="screencast" src="https://user-images.githubusercontent.com/321266/85427290-86e43700-b5b6-11ea-9e97-ffefd736c9b7.gif" width="572" height="391">

Kubelogin is designed to run as a [client-go credential plugin](https://kubernetes.io/docs/reference/access-authn-authz/authentication/#client-go-credential-plugins).
When you run kubectl, kubelogin opens the browser and you can log in to the provider.
Then kubelogin gets a token from the provider and kubectl access Kubernetes APIs with the token.
Take a look at the diagram:

![Diagram of the credential plugin](docs/credential-plugin-diagram.svg)

## Getting Started

### Setup

Install the latest release from [Homebrew](https://brew.sh/), [Krew](https://github.com/kubernetes-sigs/krew), [Chocolatey](https://chocolatey.org/packages/kubelogin) or [GitHub Releases](https://github.com/int128/kubelogin/releases).

```sh
# Homebrew (macOS and Linux)
brew install kubelogin

# Krew (macOS, Linux, Windows and ARM)
kubectl krew install oidc-login

# Chocolatey (Windows)
choco install kubelogin
```

If you install via GitHub releases, save the binary as the name `kubectl-oidc_login` on your path.
When you invoke `kubectl oidc-login`, kubectl finds it by the [naming convention of kubectl plugins](https://kubernetes.io/docs/tasks/extend-kubectl/kubectl-plugins/).
The other install methods do this for you.

You need to set up the OIDC provider, cluster role binding, Kubernetes API server and kubeconfig.
Your kubeconfig looks like this:

```yaml
users:
  - name: oidc
    user:
      exec:
        apiVersion: client.authentication.k8s.io/v1
        command: kubectl
        args:
          - oidc-login
          - get-token
          - --oidc-issuer-url=ISSUER_URL
          - --oidc-client-id=YOUR_CLIENT_ID
```

See the [setup guide](docs/setup.md) for more.

### Run

Run kubectl.

```sh
kubectl get pods
```

Kubectl executes kubelogin before calling the Kubernetes APIs.
Kubelogin automatically opens the browser, and you can log in to the provider.

After the authentication, kubelogin returns the credentials to kubectl.
Kubectl then calls the Kubernetes APIs with the credentials.

```console
% kubectl get pods
Open http://localhost:8000 for authentication
NAME                          READY   STATUS    RESTARTS   AGE
echoserver-86c78fdccd-nzmd5   1/1     Running   0          26d
```

Kubelogin stores the ID token and refresh token to the cache.
If the ID token is valid, it just returns it.
If the ID token has expired, it will refresh the token using the refresh token.
If the refresh token has expired, it will perform re-authentication.

## Troubleshooting

### Token cache

Kubelogin stores the token cache to the file system by default.
For enhanced security, it is recommended to store it to the keyring.
See the [token cache](docs/usage.md#token-cache) for details.

You can log out by deleting the token cache.

```console
% kubectl oidc-login clean
Deleted the token cache at /home/user/.kube/cache/oidc-login
```

Kubelogin will ask you to log in via the browser again.
If the browser has a cookie for the provider, you need to log out from the provider or clear the cookie.

### ID token claims

You can run `setup` command to dump the claims of an ID token from the provider.

```console
% kubectl oidc-login setup --oidc-issuer-url=ISSUER_URL --oidc-client-id=REDACTED
...
You got a token with the following claims:

{
  "sub": "********",
  "iss": "https://accounts.google.com",
  "aud": "********",
  ...
}
```

You can set `-v1` option to increase the log level.

```yaml
users:
  - name: oidc
    user:
      exec:
        apiVersion: client.authentication.k8s.io/v1
        command: kubectl
        args:
          - oidc-login
          - get-token
          - -v1
```

You can run the [acceptance test](acceptance_test) to verify if kubelogin works with your provider.

## Docs

- [Setup guide](docs/setup.md)
- [Usage and options](docs/usage.md)
- [Standalone mode](docs/standalone-mode.md)
- [System test](system_test)
- [Acceptance_test for identity providers](acceptance_test)

## Contributions

This is an open source software licensed under Apache License 2.0.
Feel free to open issues and pull requests for improving code and documents.
