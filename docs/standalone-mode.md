# Standalone mode

You can run kubelogin as a standalone command.
In this mode, you need to manually run the command before running kubectl.

Configure the kubeconfig like:

```yaml
- name: keycloak
  user:
    auth-provider:
      config:
        client-id: YOUR_CLIENT_ID
        client-secret: YOUR_CLIENT_SECRET
        idp-issuer-url: https://issuer.example.com
      name: oidc
```

Run kubelogin:

```sh
kubelogin

# or run as a kubectl plugin
kubectl oidc-login
```

It automatically opens the browser and you can log in to the provider.

<img src="keycloak-login.png" alt="keycloak-login" width="455" height="329">

After authentication, kubelogin writes the ID token and refresh token to the kubeconfig.

```
% kubelogin
Open http://localhost:8000 for authentication
You got a valid token until 2019-05-18 10:28:51 +0900 JST
Updated ~/.kubeconfig
```

Now you can access the cluster.

```
% kubectl get pods
NAME                          READY   STATUS    RESTARTS   AGE
echoserver-86c78fdccd-nzmd5   1/1     Running   0          26d
```

Your kubeconfig looks like:

```yaml
users:
- name: keycloak
  user:
    auth-provider:
      config:
        client-id: YOUR_CLIENT_ID
        client-secret: YOUR_CLIENT_SECRET
        idp-issuer-url: https://issuer.example.com
        id-token: ey...       # kubelogin will add or update the ID token here
        refresh-token: ey...  # kubelogin will add or update the refresh token here
      name: oidc
```

If the ID token is valid, kubelogin does nothing.

```
% kubelogin
You already have a valid token until 2019-05-18 10:28:51 +0900 JST
```

If the ID token has expired, kubelogin will refresh the token using the refresh token in the kubeconfig.
If the refresh token has expired, kubelogin will proceed the authentication.


## Usage

Kubelogin supports the following options:

```
% kubelogin -h
Login to the OpenID Connect provider and update the kubeconfig

Usage:
  kubelogin [flags]
  kubelogin [command]

Examples:
  # Login to the provider using the authorization code flow.
  kubelogin

  # Login to the provider using the resource owner password credentials flow.
  kubelogin --username USERNAME --password PASSWORD

  # Run as a credential plugin.
  kubelogin get-token --oidc-issuer-url=https://issuer.example.com

Available Commands:
  get-token   Run as a kubectl credential plugin
  help        Help about any command
  version     Print the version information

Flags:
      --kubeconfig string              Path to the kubeconfig file
      --context string                 The name of the kubeconfig context to use
      --user string                    The name of the kubeconfig user to use. Prior to --context
      --certificate-authority string   Path to a cert file for the certificate authority
      --insecure-skip-tls-verify       If true, the server's certificate will not be checked for validity. This will make your HTTPS connections insecure
  -v, --v int                          If set to 1 or greater, it shows debug log
      --listen-port ints               Port to bind to the local server. If multiple ports are given, it will try the ports in order (default [8000,18000])
      --skip-open-browser              If true, it does not open the browser on authentication
      --username string                If set, perform the resource owner password credentials grant
      --password string                If set, use the password instead of asking it
  -h, --help                           help for kubelogin
```

### Kubeconfig

You can set path to the kubeconfig file by the option or the environment variable just like kubectl.
It defaults to `~/.kube/config`.

```sh
# by the option
kubelogin --kubeconfig /path/to/kubeconfig

# by the environment variable
KUBECONFIG="/path/to/kubeconfig1:/path/to/kubeconfig2" kubelogin
```

If you set multiple files, kubelogin will find the file which has the current authentication (i.e. `user` and `auth-provider`) and write a token to it.

Kubelogin supports the following keys of `auth-provider` in a kubeconfig.
See [kubectl authentication](https://kubernetes.io/docs/reference/access-authn-authz/authentication/#using-kubectl) for more.

Key | Direction | Value
----|-----------|------
`idp-issuer-url`                  | Read (Mandatory) | Issuer URL of the provider.
`client-id`                       | Read (Mandatory) | Client ID of the provider.
`client-secret`                   | Read (Mandatory) | Client Secret of the provider.
`idp-certificate-authority`       | Read | CA certificate path of the provider.
`idp-certificate-authority-data`  | Read | Base64 encoded CA certificate of the provider.
`extra-scopes`                    | Read | Scopes to request to the provider (comma separated).
`id-token`                        | Write | ID token got from the provider.
`refresh-token`                   | Write | Refresh token got from the provider.

### Extra scopes

You can set the extra scopes to request to the provider by `extra-scopes` in the kubeconfig.

```sh
kubectl config set-credentials keycloak --auth-provider-arg extra-scopes=email
```

Currently kubectl does not accept multiple scopes, so you need to edit the kubeconfig as like:

```sh
kubectl config set-credentials keycloak --auth-provider-arg extra-scopes=SCOPES
sed -i '' -e s/SCOPES/email,profile/ $KUBECONFIG
```

### CA Certificates

You can use your self-signed certificates for the provider.

```sh
kubectl config set-credentials keycloak \
  --auth-provider-arg idp-certificate-authority=$HOME/.kube/keycloak-ca.pem
```
