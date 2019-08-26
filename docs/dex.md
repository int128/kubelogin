# Getting Started with dex and GitHub

## Prerequisite

- You have a GitHub account.
- You can configure the Kubernetes API server.
- `kubectl` and `kubelogin` are installed.

## 1. Setup GitHub OAuth

Open [GitHub OAuth Apps](https://github.com/settings/developers) and create an application with the following setting:

- Application name: (any)
- Homepage URL: `https://dex.example.com`
- Authorization callback URL: `https://dex.example.com/callback`

## 2. Setup dex

Configure the dex with the following config:

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
- id: kubernetes
  name: Kubernetes
  redirectURIs:
    - http://localhost:8000
    - http://localhost:18000
  secret: YOUR_DEX_CLIENT_SECRET
```

Now test authentication with the dex.

```sh
kubectl oidc-login get-token -v1 \
  --oidc-issuer-url=https://dex.example.com \
  --oidc-client-id=kubernetes \
  --oidc-client-secret=YOUR_DEX_CLIENT_SECRET
```

You should get claims like:

```
I0827 12:29:03.086531   23722 get_token.go:59] the ID token has the claim: aud=kubernetes
I0827 12:29:03.086553   23722 get_token.go:59] the ID token has the claim: iss=https://dex.example.com
I0827 12:29:03.086561   23722 get_token.go:59] the ID token has the claim: sub=YOUR_SUBJECT
```

## 3. Setup Kubernetes API server

Configure your Kubernetes API server accepts [OpenID Connect Tokens](https://kubernetes.io/docs/reference/access-authn-authz/authentication/#openid-connect-tokens).

```
--oidc-issuer-url=https://dex.example.com
--oidc-client-id=kubernetes
```

If you are using [kops](https://github.com/kubernetes/kops), run `kops edit cluster` and add the following spec:

```yaml
spec:
  kubeAPIServer:
    oidcIssuerURL: https://dex.example.com
    oidcClientID: kubernetes
```

## 4. Create a role binding

Here assign the `cluster-admin` role to your subject.

```yaml
kind: ClusterRoleBinding
apiVersion: rbac.authorization.k8s.io/v1
metadata:
  name: keycloak-admin-group
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: cluster-admin
subjects:
- kind: User
  name: YOUR_SUBJECT
```

You can create a custom role and assign it as well.

## 5. Setup kubeconfig

Configure the kubeconfig like:

```yaml
apiVersion: v1
clusters:
- cluster:
    server: https://api.example.com
  name: example.k8s.local
contexts:
- context:
    cluster: example.k8s.local
    user: dex
  name: dex@example.k8s.local
current-context: dex@example.k8s.local
kind: Config
preferences: {}
users:
- name: dex
  user:
    exec:
      apiVersion: client.authentication.k8s.io/v1beta1
      command: kubectl
      args:
      - oidc-login
      - get-token
      - --oidc-issuer-url=https://dex.example.com
      - --oidc-client-id=kubernetes
      - --oidc-client-secret=YOUR_DEX_CLIENT_SECRET
```

You can share the kubeconfig to your team members for on-boarding.

## 6. Run kubectl

Make sure you can access the Kubernetes cluster.

```
% kubectl get nodes
Open http://localhost:8000 for authentication
You got a valid token until 2019-05-16 22:03:13 +0900 JST
Updated ~/.kubeconfig
NAME                                    STATUS    ROLES     AGE       VERSION
ip-1-2-3-4.us-west-2.compute.internal   Ready     node      21d       v1.9.6
ip-1-2-3-5.us-west-2.compute.internal   Ready     node      20d       v1.9.6
```
