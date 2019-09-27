# Getting Started with Google Identity Platform

Prerequisite:

- You have a Google account.
- You have an administrator role of the Kubernetes cluster.
- You can configure the Kubernetes API server.
- `kubectl` and `kubelogin` are installed to your computer.


## 1. Set up the OpenID Connect Provider

Open [Google APIs Console](https://console.developers.google.com/apis/credentials) and create an OAuth client with the following setting:

- Application Type: Other


## 2. Verify authentication

Run the following command:

```sh
kubectl oidc-login setup \
  --oidc-issuer-url=https://accounts.google.com \
  --oidc-client-id=YOUR_CLIENT_ID \
  --oidc-client-secret=YOUR_CLIENT_SECRET
```

It will open the browser and you can log in to the provider.


## 3. Bind a role

Bind the `cluster-admin` role to you.
Apply the following manifest:

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
  name: https://accounts.google.com#YOUR_SUBJECT
```

As well as you can create a custom role and bind it.


## 4. Set up the Kubernetes API server

Add the following options to the kube-apiserver:

```
--oidc-issuer-url=https://accounts.google.com
--oidc-client-id=YOUR_CLIENT_ID
```

See [OpenID Connect Tokens](https://kubernetes.io/docs/reference/access-authn-authz/authentication/#openid-connect-tokens) for details.

If you are using [kops](https://github.com/kubernetes/kops), run `kops edit cluster` and append the following settings:

```yaml
spec:
  kubeAPIServer:
    oidcIssuerURL: https://accounts.google.com
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
      - --oidc-issuer-url=https://accounts.google.com
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
