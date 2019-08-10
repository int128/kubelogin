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

```
--oidc-issuer-url=https://accounts.google.com
--oidc-client-id=YOUR_CLIENT_ID.apps.googleusercontent.com
```

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

## 4. Setup kubeconfig

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
    user: google
  name: google@example.k8s.local
current-context: google@example.k8s.local
kind: Config
preferences: {}
users:
- name: google
  user:
    exec:
      apiVersion: client.authentication.k8s.io/v1beta1
      command: kubelogin
      args:
      - get-token
      - --oidc-issuer-url=https://accounts.google.com
      - --oidc-client-id=YOUR_CLIENT_ID.apps.googleusercontent.com
      - --oidc-client-secret=YOUR_CLIENT_SECRET
```

You can share the kubeconfig to your team members for on-boarding.

## 5. Run kubectl

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
