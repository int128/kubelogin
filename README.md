# kubelogin [![CircleCI](https://circleci.com/gh/int128/kubelogin.svg?style=shield)](https://circleci.com/gh/int128/kubelogin)

`kubelogin` is a command to get an OpenID Connect (OIDC) token for `kubectl` authentication.


## Getting Started with Google Account

### 1. Setup Google API

Open [Google APIs Console](https://console.developers.google.com/apis/credentials) and create an OAuth client as follows:

- Application Type: Web application
- Redirect URL: `http://localhost:8000/`

### 2. Setup Kubernetes API Server

Setup the Kubernetes API Server accepts an ID token.

If you are using [kops](https://github.com/kubernetes/kops), run `kops edit cluster` and append the following settings:

```yaml
spec:
  kubeAPIServer:
    oidcIssuerURL: https://accounts.google.com
    oidcClientID: YOUR_CLIENT_ID.apps.googleusercontent.com
```

### 3. Assign a role

Here assign the `cluster-admin` role to your user.

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

### 4. Setup kubectl and kubelogin

Setup `kubectl` to authenticate with your identity provider.

```sh
kubectl config set-credentials CLUSTER_NAME \
  --auth-provider oidc \
  --auth-provider-arg idp-issuer-url=https://accounts.google.com \
  --auth-provider-arg client-id=YOUR_CLIENT_ID.apps.googleusercontent.com \
  --auth-provider-arg client-secret=YOUR_CLIENT_SECRET
```

Run `kubelogin` and open http://localhost:8000 in your browser.

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


## Getting Started with Keycloak

### 1. Setup Keycloak

Create an OIDC client as follows:

- Redirect URL: `http://localhost:8000/`
- Issuer URL: `https://keycloak.example.com/auth/realms/YOUR_REALM`
- Client ID: `kubernetes`
- Groups claim: `groups`

Then create a group `kubernetes:admin` and join to it.

### 2. Setup Kubernetes API Server

Setup the Kubernetes API Server accepts an ID token.

If you are using [kops](https://github.com/kubernetes/kops), run `kops edit cluster` and append the following settings:

```yaml
spec:
  kubeAPIServer:
    oidcIssuerURL: https://keycloak.example.com/auth/realms/YOUR_REALM
    oidcClientID: kubernetes
    oidcGroupsClaim: groups
```

### 3. Assign a role

Here assign the `cluster-admin` role to the `kubernetes:admin` group.

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
- kind: Group
  name: /kubernetes:admin
```

### 4. Setup kubectl and kubelogin

Setup `kubectl` to authenticate with your identity provider.

```sh
kubectl config set-credentials CLUSTER_NAME \
  --auth-provider oidc \
  --auth-provider-arg idp-issuer-url=https://keycloak.example.com/auth/realms/YOUR_REALM \
  --auth-provider-arg client-id=kubernetes \
  --auth-provider-arg client-secret=YOUR_CLIENT_SECRET
```

Run `kubelogin` and make sure you can access to the cluster.


## Tips

### Config file

You can set the environment variable `KUBECONFIG` to point the config file.
Default to `~/.kube/config`.

```sh
export KUBECONFIG="$PWD/.kubeconfig"
```

### Setup script

In actual team operation, you can share the following script to your team members for easy setup.

```sh
#!/bin/sh -xe
CLUSTER_NAME="hello.k8s.local"

export KUBECONFIG="$PWD/.kubeconfig"

kubectl config set-cluster "$CLUSTER_NAME" \
  --server https://api-xxx.xxx.elb.amazonaws.com \
  --certificate-authority "$PWD/cluster.crt"

kubectl config set-credentials "$CLUSTER_NAME" \
  --auth-provider oidc \
  --auth-provider-arg idp-issuer-url=https://accounts.google.com \
  --auth-provider-arg client-id=YOUR_CLIENT_ID.apps.googleusercontent.com \
  --auth-provider-arg client-secret=YOUR_CLIENT_SECRET

kubectl config set-context "$CLUSTER_NAME" --cluster "$CLUSTER_NAME" --user "$CLUSTER_NAME"
kubectl config use-context "$CLUSTER_NAME"
```


## Contributions

This is an open source software licensed under Apache License 2.0.
Feel free to open issues and pull requests.

### Build

```sh
go get github.com/int128/kubelogin
```

### Release

CircleCI publishes the build to GitHub. See [.circleci/config.yml](.circleci/config.yml).
