# Kubernetes OpenID Connection authentication

This document guides how to set up Kubernetes OpenID Connect (OIDC) authentication.
Let's see the following steps:

1. Set up the OIDC provider
1. Verify authentication
1. Bind a cluster role
1. Set up the Kubernetes API server
1. Set up the kubeconfig
1. Verify cluster access


## 1. Set up the OIDC provider

### Google Identity Platform

You can log in with a Google account.

Open [Google APIs Console](https://console.developers.google.com/apis/credentials) and create an OAuth client with the following setting:

- Application Type: Other

Check the client ID and secret.
Replace the following variables in the later sections.

Variable                | Value
------------------------|------
`ISSUER_URL`            | `https://accounts.google.com`
`YOUR_CLIENT_ID`        | `xxx.apps.googleusercontent.com`
`YOUR_CLIENT_SECRET`    | random string

### Keycloak

You can log in with a user of Keycloak.
Make sure you have an administrator role of the Keycloak realm.

Open Keycloak and create an OIDC client as follows:

- Client ID: `YOUR_CLIENT_ID`
- Valid Redirect URLs:
    - `http://localhost:8000`
    - `http://localhost:18000` (used if the port 8000 is already in use)
- Issuer URL: `https://keycloak.example.com/auth/realms/YOUR_REALM`

You can associate client roles by adding the following mapper:

- Name: `groups`
- Mapper Type: `User Client Role`
- Client ID: `YOUR_CLIENT_ID`
- Client Role prefix: `kubernetes:`
- Token Claim Name: `groups`
- Add to ID token: on

For example, if you have `admin` role of the client, you will get a JWT with the claim `{"groups": ["kubernetes:admin"]}`.

Replace the following variables in the later sections.

Variable                | Value
------------------------|------
`ISSUER_URL`            | `https://keycloak.example.com/auth/realms/YOUR_REALM`
`YOUR_CLIENT_ID`        | `YOUR_CLIENT_ID`
`YOUR_CLIENT_SECRET`    | random string

### Dex with GitHub

You can log in with a GitHub account.

Open [GitHub OAuth Apps](https://github.com/settings/developers) and create an application with the following setting:

- Application name: (any)
- Homepage URL: `https://dex.example.com`
- Authorization callback URL: `https://dex.example.com/callback`

Deploy [Dex](https://github.com/dexidp/dex) with the following config:

```yaml
issuer: https://dex.example.com
connectors:
- type: github
  id: github
  name: GitHub
  config:
    clientID: YOUR_GITHUB_CLIENT_ID
    clientSecret: YOUR_GITHUB_CLIENT_SECRET
    redirectURI: https://dex.example.com/callback
staticClients:
- id: YOUR_CLIENT_ID
  name: Kubernetes
  redirectURIs:
  - http://localhost:8000
  - http://localhost:18000
  secret: YOUR_DEX_CLIENT_SECRET
```

Replace the following variables in the later sections.

Variable                | Value
------------------------|------
`ISSUER_URL`            | `https://dex.example.com`
`YOUR_CLIENT_ID`        | `YOUR_CLIENT_ID`
`YOUR_CLIENT_SECRET`    | `YOUR_DEX_CLIENT_SECRET`

### Okta

You can log in with an Okta user.
Okta supports [the authorization code flow with PKCE](https://developer.okta.com/docs/guides/implement-auth-code-pkce/overview/)
and this section explains how to set up it.

Open your Okta organization and create an application with the following options:

- Application type: Native
- Initiate login URI: `http://localhost:8000`
- Login redirect URIs:
    - `http://localhost:8000`
    - `http://localhost:18000` (used if the port 8000 is already in use)
- Allowed grant types: Authorization Code
- Client authentication: Use PKCE (for public clients)

Replace the following variables in the later sections.

Variable                | Value
------------------------|------
`ISSUER_URL`            | `https://YOUR_ORGANIZATION.okta.com`
`YOUR_CLIENT_ID`        | random string

You do not need to set `YOUR_CLIENT_SECRET`.

If you need `groups` claim for access control,
see [jetstack/okta-kubectl-auth](https://github.com/jetstack/okta-kubectl-auth/blob/master/docs/okta-setup.md) and [#250](https://github.com/int128/kubelogin/issues/250).

### Ping Identity

Login with an account that has permissions to create applications.
Create an OIDC application with the following configuration:

- Redirect URIs:
    - `http://localhost:8000`
    - `http://localhost:18000` (used if the port 8000 is already in use)
- Grant type: Authorization Code
- PKCE Enforcement: Required

Leverage the following variables in the next steps.

Variable                | Value
------------------------|------
`ISSUER_URL`            | `https://auth.pingone.com/<PingOne Tenant Id>/as`
`YOUR_CLIENT_ID`        |  random string

`YOUR_CLIENT_SECRET` is not required for this configuration.

## 2. Verify authentication

Run the following command:

```sh
kubectl oidc-login setup \
  --oidc-issuer-url=ISSUER_URL \
  --oidc-client-id=YOUR_CLIENT_ID \
  --oidc-client-secret=YOUR_CLIENT_SECRET
```

It launches the browser and navigates to `http://localhost:8000`.
Please log in to the provider.

You can set extra options, for example, extra scope or CA certificate.
See also the full options.

```sh
kubectl oidc-login setup --help
```


## 3. Bind a cluster role

Here bind `cluster-admin` role to you.

```sh
kubectl create clusterrolebinding oidc-cluster-admin --clusterrole=cluster-admin --user='ISSUER_URL#YOUR_SUBJECT'
```

As well as you can create a custom cluster role and bind it.


## 4. Set up the Kubernetes API server

Add the following flags to kube-apiserver:

```
--oidc-issuer-url=ISSUER_URL
--oidc-client-id=YOUR_CLIENT_ID
```

See [Kubernetes Authenticating: OpenID Connect Tokens](https://kubernetes.io/docs/reference/access-authn-authz/authentication/#openid-connect-tokens) for the all flags.

If you are using [kops](https://github.com/kubernetes/kops), run `kops edit cluster` and append the following settings:

```yaml
spec:
  kubeAPIServer:
    oidcIssuerURL: ISSUER_URL
    oidcClientID: YOUR_CLIENT_ID
```

If you are using [kube-aws](https://github.com/kubernetes-incubator/kube-aws), append the following settings to the `cluster.yaml`:

```yaml
       oidc:
         enabled: true
         issuerUrl: ISSUER_URL
         clientId: YOUR_CLIENT_ID
```


## 5. Set up the kubeconfig

Add `oidc` user to the kubeconfig.

```sh
kubectl config set-credentials oidc \
  --exec-api-version=client.authentication.k8s.io/v1beta1 \
  --exec-command=kubectl \
  --exec-arg=oidc-login \
  --exec-arg=get-token \
  --exec-arg=--oidc-issuer-url=ISSUER_URL \
  --exec-arg=--oidc-client-id=YOUR_CLIENT_ID \
  --exec-arg=--oidc-client-secret=YOUR_CLIENT_SECRET
```


## 6. Verify cluster access

Make sure you can access the Kubernetes cluster.

```sh
kubectl --user=oidc cluster-info
```

You can switch the current context to oidc.

```sh
kubectl config set-context --current --user=oidc
```

You can share the kubeconfig to your team members for on-boarding.
