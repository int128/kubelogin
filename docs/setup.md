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

Kubelogin supports the authentication flows such as Device Authorization Grant or Authorization Code Flow.
For the details of flows supported in Kubelogin, see the [usage](usage.md).
For the details of your provider, ask the administrator of your provider.

## 2. Authenticate with the OpenID Connect Provider

Run the following command to show the instruction to set up the configuration:

```sh
kubectl oidc-login setup --oidc-issuer-url=ISSUER_URL --oidc-client-id=YOUR_CLIENT_ID
```

Set the following flags:

- Set the issuer URL of your OpenID Connect provider to `--oidc-issuer-url`.
- Set the client ID for your OpenID Connect provider to `--oidc-client-id`.
- If your provider requires a client secret, set `--oidc-client-secret`.

If your provider supports the Device Authorization Grant, set `--grant-type=device-code`.
It launches the browser and navigates to the authentication page of your provider.

If your provider supports the Authorization Code Flow, set `--grant-type=authcode`.
It starts a local server for the authentication.
It launches the browser and navigates to the authentication page of your provider.

You can see the full options:

```sh
kubectl oidc-login setup --help
```

## 3. Bind a cluster role

You can run the following command to bind `cluster-admin` role to you:

```sh
kubectl create clusterrolebinding oidc-cluster-admin --clusterrole=cluster-admin --user='ISSUER_URL#YOUR_SUBJECT'
```

## 4. Set up the Kubernetes API server

Add the following flags to kube-apiserver:

```
--oidc-issuer-url=ISSUER_URL
--oidc-client-id=YOUR_CLIENT_ID
```

See [Kubernetes Authenticating: OpenID Connect Tokens](https://kubernetes.io/docs/reference/access-authn-authz/authentication/#openid-connect-tokens) for the all flags.

## 5. Set up the kubeconfig

Add `oidc` user to the kubeconfig.

```sh
kubectl config set-credentials oidc \
  --exec-interactive-mode=Never \
  --exec-api-version=client.authentication.k8s.io/v1 \
  --exec-command=kubectl \
  --exec-arg=oidc-login \
  --exec-arg=get-token \
  --exec-arg=--oidc-issuer-url=ISSUER_URL \
  --exec-arg=--oidc-client-id=YOUR_CLIENT_ID
```

If your provider requires a client secret, add `--oidc-client-secret=YOUR_CLIENT_SECRET`.

For security, it is recommended to add `--token-cache-storage=keyring` to store the token cache to the keyring instead of the file system.
If you encounter an error, see the [token cache](usage.md#token-cache) for details.

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
