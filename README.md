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
brew install int128/kubelogin/kubelogin

# Krew (macOS, Linux, Windows and ARM)
kubectl krew install oidc-login

# Chocolatey (Windows)
choco install kubelogin
```

If you install via GitHub releases, you need to put the `kubelogin` binary on your path under the name `kubectl-oidc_login` so that the [kubectl plugin mechanism](https://kubernetes.io/docs/tasks/extend-kubectl/kubectl-plugins/) can find it when you invoke `kubectl oidc-login`. The other install methods do this for you.

You need to set up the OIDC provider, cluster role binding, Kubernetes API server and kubeconfig.
The kubeconfig looks like:

```yaml
users:
- name: oidc
  user:
    exec:
      apiVersion: client.authentication.k8s.io/v1beta1
      command: kubectl
      args:
      - oidc-login
      - get-token
      - --oidc-issuer-url=ISSUER_URL
      - --oidc-client-id=YOUR_CLIENT_ID
      - --oidc-client-secret=YOUR_CLIENT_SECRET
```

See [setup guide](docs/setup.md) for more.


### Run

Run kubectl.

```sh
kubectl get pods
```

Kubectl executes kubelogin before calling the Kubernetes APIs.
Kubelogin automatically opens the browser, and you can log in to the provider.

<img src="docs/keycloak-login.png" alt="keycloak-login" width="455" height="329">

After authentication, kubelogin returns the credentials to kubectl and kubectl then calls the Kubernetes APIs with these credentials.

```
% kubectl get pods
Open http://localhost:8000 for authentication
NAME                          READY   STATUS    RESTARTS   AGE
echoserver-86c78fdccd-nzmd5   1/1     Running   0          26d
```

Kubelogin writes the ID token and refresh token to the token cache file.

If the cached ID token is valid, kubelogin just returns it.
If the cached ID token has expired, kubelogin will refresh the token using the refresh token.
If the refresh token has expired, kubelogin will perform re-authentication (you will have to login via browser again).


### Troubleshoot

You can log out by removing the token cache directory (default `~/.kube/cache/oidc-login`).
Kubelogin will ask you to login via browser again if the token cache file does not exist i.e., it starts with a clean slate

You can dump claims of an ID token by `setup` command.

```console
% kubectl oidc-login setup --oidc-issuer-url https://accounts.google.com --oidc-client-id REDACTED --oidc-client-secret REDACTED
...
You got a token with the following claims:

{
  "sub": "********",
  "iss": "https://accounts.google.com",
  "aud": "********",
  ...
}
```

You can increase the log level by `-v1` option.

```yaml
users:
- name: oidc
  user:
    exec:
      apiVersion: client.authentication.k8s.io/v1beta1
      command: kubectl
      args:
      - oidc-login
      - get-token
      - -v1
```

You can verify kubelogin works with your provider using [acceptance test](acceptance_test).


## Docs

- [Setup guide](docs/setup.md)
- [Usage and options](docs/usage.md)
- [Standalone mode](docs/standalone-mode.md)
- [System test](system_test)
- [Acceptance_test for identity providers](acceptance_test)


## Contributions

This is an open source software licensed under Apache License 2.0.
Feel free to open issues and pull requests for improving code and documents.

This software is developed with [GoLand](https://www.jetbrains.com/go/) licensed for open source development.
Special thanks for the support.
