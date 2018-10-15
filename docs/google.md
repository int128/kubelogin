# Getting Started with Google Identity Platform

## Prerequisite

- You have a Google account.
- You have the Cluster Admin role of the Kubernetes cluster.
- You can configure the Kubernetes API server.
- `kubectl` and `kubelogin` are installed to your computer.

## 1. Setup Google API

Open [Google APIs Console](https://console.developers.google.com/apis/credentials) and create an OAuth client with the following setting:

- Application Type: Other

## 2. Setup Kubernetes API server

Configure your Kubernetes API Server accepts [OpenID Connect Tokens](https://kubernetes.io/docs/reference/access-authn-authz/authentication/#openid-connect-tokens).

### kops

If you are using [kops](https://github.com/kubernetes/kops), run `kops edit cluster` and append the following settings:

```yaml
spec:
  kubeAPIServer:
    oidcIssuerURL: https://accounts.google.com
    oidcClientID: YOUR_CLIENT_ID.apps.googleusercontent.com
```

## 3. Setup Kubernetes cluster

Here assign the `cluster-admin` role to you.

```yaml
kind: ClusterRoleBinding
apiVersion: rbac.authorization.k8s.io/v1
metadata:
  name: oidc-admin-group
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: cluster-admin
subjects:
- kind: User
  name: https://accounts.google.com#1234567890
```

You can create a custom role and assign it as well.

## 4. Setup kubectl

Configure `kubectl` for the OIDC authentication.

```sh
kubectl config set-credentials NAME \
  --auth-provider oidc \
  --auth-provider-arg idp-issuer-url=https://accounts.google.com \
  --auth-provider-arg client-id=YOUR_CLIENT_ID.apps.googleusercontent.com \
  --auth-provider-arg client-secret=YOUR_CLIENT_SECRET
```

## 5. Run kubelogin

Run `kubelogin`.

```
% kubelogin
2018/08/10 10:36:38 Reading .kubeconfig
2018/08/10 10:36:38 Using current context: hello.k8s.local
2018/08/10 10:36:41 Open http://localhost:8000 for authorization
2018/08/10 10:36:45 GET /
2018/08/10 10:37:07 GET /?state=...&session_state=...&code=ey...
2018/08/10 10:37:08 Updated .kubeconfig
```

Now your `~/.kube/config` should be like:

```yaml
users:
- name: hello.k8s.local
  user:
    auth-provider:
      config:
        idp-issuer-url: https://accounts.google.com
        client-id: YOUR_CLIENT_ID.apps.googleusercontent.com
        client-secret: YOUR_SECRET
        id-token: ey...       # kubelogin will update ID token here
        refresh-token: ey...  # kubelogin will update refresh token here
      name: oidc
```

Make sure you can access to the Kubernetes cluster.

```
% kubectl get nodes
NAME                                    STATUS    ROLES     AGE       VERSION
ip-1-2-3-4.us-west-2.compute.internal   Ready     node      21d       v1.9.6
ip-1-2-3-5.us-west-2.compute.internal   Ready     node      20d       v1.9.6
```
