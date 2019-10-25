# Kubernetes OpenID Connection authentication

This document guides how to set up the Kubernetes OpenID Connect (OIDC) authentication.
Let's see the following steps:

1. Set up the OIDC provider
1. Verify authentication
1. Bind a role
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

Open the Keycloak and create an OIDC client as follows:

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

For example, if you have the `admin` role of the client, you will get a JWT with the claim `{"groups": ["kubernetes:admin"]}`.

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

Deploy the [dex](https://github.com/dexidp/dex) with the following config:

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

Open your Okta organization and create an application with the following options:

- Login redirect URIs:
    - `http://localhost:8000`
    - `http://localhost:18000` (used if the port 8000 is already in use)
- Grant type allowed: Authorization Code

Replace the following variables in the later sections.

Variable                | Value
------------------------|------
`ISSUER_URL`            | `https://YOUR_ORGANIZATION.okta.com`
`YOUR_CLIENT_ID`        | random string
`YOUR_CLIENT_SECRET`    | random string


## 2. Verify authentication

Run the following command:

```sh
kubectl oidc-login setup \
  --oidc-issuer-url=ISSUER_URL \
  --oidc-client-id=YOUR_CLIENT_ID \
  --oidc-client-secret=YOUR_CLIENT_SECRET
```

It will open the browser and you can log in to the provider.
Then it will show the instruction.


## 3. Bind a role

Bind the `cluster-admin` role to you.
Apply the following manifest:

```yaml
kind: ClusterRoleBinding
apiVersion: rbac.authorization.k8s.io/v1
metadata:
  name: oidc-cluster-admin
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: cluster-admin
subjects:
- kind: User
  name: ISSUER_URL#YOUR_SUBJECT
```

```sh
kubectl apply -f oidc-cluster-admin.yaml
```

As well as you can create a custom role and bind it.


## 4. Set up the Kubernetes API server

Add the following options to the kube-apiserver:

```
--oidc-issuer-url=ISSUER_URL
--oidc-client-id=YOUR_CLIENT_ID
```

See [OpenID Connect Tokens](https://kubernetes.io/docs/reference/access-authn-authz/authentication/#openid-connect-tokens) for details.

If you are using [kops](https://github.com/kubernetes/kops), run `kops edit cluster` and append the following settings:

```yaml
spec:
  kubeAPIServer:
    oidcIssuerURL: ISSUER_URL
    oidcClientID: YOUR_CLIENT_ID
```


## 5. Set up the kubeconfig

Add the following user to the kubeconfig:

```yaml
users:
- name: google
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

You can share the kubeconfig to your team members for on-boarding.


## 6. Verify cluster access

Make sure you can access the Kubernetes cluster.

```
% kubectl get nodes
Open http://localhost:8000 for authentication
You got a valid token until 2019-05-16 22:03:13 +0900 JST
NAME                                    STATUS    ROLES     AGE       VERSION
ip-1-2-3-4.us-west-2.compute.internal   Ready     node      21d       v1.9.6
ip-1-2-3-5.us-west-2.compute.internal   Ready     node      20d       v1.9.6
```
