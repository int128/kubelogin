# Usage

Kubelogin supports the following options:

```
Usage:
  kubelogin get-token [flags]

Flags:
      --oidc-issuer-url string                          Issuer URL of the provider (mandatory)
      --oidc-client-id string                           Client ID of the provider (mandatory)
      --oidc-client-secret string                       Client secret of the provider
      --oidc-redirect-url string                        [authcode, authcode-keyboard] Redirect URL
      --oidc-extra-scope strings                        Scopes to request to the provider
      --oidc-use-access-token                           Instead of using the id_token, use the access_token to authenticate to Kubernetes
      --force-refresh                                   If set, refresh the ID token regardless of its expiration time
      --token-cache-dir string                          Path to a directory of the token cache (default "~/.kube/cache/oidc-login")
      --token-cache-storage string                      Storage for the token cache. One of (disk|keyring|none) (default "disk")
      --certificate-authority stringArray               Path to a cert file for the certificate authority
      --certificate-authority-data stringArray          Base64 encoded cert for the certificate authority
      --insecure-skip-tls-verify                        [SECURITY RISK] If set, the server's certificate will not be checked for validity
      --tls-renegotiation-once                          If set, allow a remote server to request renegotiation once per connection
      --tls-renegotiation-freely                        If set, allow a remote server to repeatedly request renegotiation
      --oidc-pkce-method string                         PKCE code challenge method. Automatically determined by default. One of (auto|no|S256) (default "auto")
      --grant-type string                               Authorization grant type to use. One of (auto|authcode|authcode-keyboard|password|device-code) (default "auto")
      --listen-address strings                          [authcode] Address to bind to the local server. If multiple addresses are set, it will try binding in order (default [127.0.0.1:8000,127.0.0.1:18000])
      --skip-open-browser                               [authcode] Do not open the browser automatically
      --browser-command string                          [authcode] Command to open the browser
      --authentication-timeout-sec int                  [authcode] Timeout of authentication in seconds (default 180)
      --local-server-cert string                        [authcode] Certificate path for the local server
      --local-server-key string                         [authcode] Certificate key path for the local server
      --open-url-after-authentication string            [authcode] If set, open the URL in the browser after authentication
      --oidc-auth-request-extra-params stringToString   [authcode, authcode-keyboard, client-credentials] Extra query parameters to send with an authentication request (default [])
      --username string                                 [password] Username for resource owner password credentials grant
      --password string                                 [password] Password for resource owner password credentials grant
  -h, --help                                            help for get-token

Global Flags:
      --add_dir_header                   If true, adds the file directory to the header of the log messages
      --alsologtostderr                  log to standard error as well as files (no effect when -logtostderr=true)
      --log_backtrace_at traceLocation   when logging hits line file:N, emit a stack trace (default :0)
      --log_dir string                   If non-empty, write log files in this directory (no effect when -logtostderr=true)
      --log_file string                  If non-empty, use this log file (no effect when -logtostderr=true)
      --log_file_max_size uint           Defines the maximum size a log file can grow to (no effect when -logtostderr=true). Unit is megabytes. If the value is 0, the maximum file size is unlimited. (default 1800)
      --logtostderr                      log to standard error instead of files (default true)
      --one_output                       If true, only write logs to their native severity level (vs also writing to each lower severity level; no effect when -logtostderr=true)
      --skip_headers                     If true, avoid header prefixes in the log messages
      --skip_log_headers                 If true, avoid headers when opening log files (no effect when -logtostderr=true)
      --stderrthreshold severity         logs at or above this threshold go to stderr when writing to files and stderr (no effect when -logtostderr=true or -alsologtostderr=true) (default 2)
  -v, --v Level                          number for the log level verbosity
      --vmodule moduleSpec               comma-separated list of pattern=N settings for file-filtered logging
```

## Options

### Authentication timeout

By default, you need to log in to your provider in the browser within 3 minutes.
This prevents a process from remaining forever.
You can change the timeout by the following flag:

```yaml
- --authentication-timeout-sec=60
```

For now this timeout works only for the authorization code flow.

### Extra scopes

You can set the extra scopes to request to the provider by `--oidc-extra-scope`.

```yaml
- --oidc-extra-scope=email
- --oidc-extra-scope=profile
```

### PKCE

Kubelogin automatically uses the PKCE if the provider supports it.
It determines the code challenge method by the `code_challenge_methods_supported` claim of the OpenID Connect Discovery document.

If your provider does not return a valid `code_challenge_methods_supported` claim,
you can enforce the code challenge method by `--oidc-pkce-method`.

```yaml
- --oidc-pkce-method=S256
```

For the most providers, you don't need to set this option explicitly.

### CA certificate

You can use your self-signed certificate for the provider.

```yaml
- --certificate-authority=/home/user/.kube/keycloak-ca.pem
- --certificate-authority-data=LS0t...
```

### HTTP proxy

You can set the following environment variables if you are behind a proxy: `HTTP_PROXY`, `HTTPS_PROXY` and `NO_PROXY`.
See also [net/http#ProxyFromEnvironment](https://golang.org/pkg/net/http/#ProxyFromEnvironment).

### Token cache

Kubelogin stores the token cache to the file system by default.

You can store the token cache to the OS keyring for enhanced security.
It depends on [zalando/go-keyring](https://github.com/zalando/go-keyring).

```yaml
- --token-cache-storage=keyring
```

You can delete the token cache by the clean command.

```console
% kubectl oidc-login clean
Deleted the token cache at /home/user/.kube/cache/oidc-login
Deleted the token cache from the keyring
```

For systems with immutable storage and no keyring, a cache type of none is available.

### Home directory expansion

If a value in the following options begins with a tilde character `~`, it is expanded to the home directory.

- `--certificate-authority`
- `--local-server-cert`
- `--local-server-key`
- `--token-cache-dir`

## Authentication flows

Kubelogin support the following flows:

- [Authorization code flow](#authorization-code-flow)
- [Authorization code flow with a keyboard](#authorization-code-flow-with-a-keyboard)
- [Device authorization grant](#device-authorization-grant)
- [Resource owner password credentials grant](#resource-owner-password-credentials-grant)
- [Client Credentials flow](#client-credentials-flow)

### Authorization code flow

Kubelogin performs the [authorization code flow](https://openid.net/specs/openid-connect-core-1_0.html#CodeFlowAuth) by default.

It starts the local server at port 8000 or 18000 by default.
You need to register the following redirect URIs to the provider:

- `http://localhost:8000`
- `http://localhost:18000` (used if port 8000 is already in use)

You can change the listening address.

```yaml
- --listen-address=127.0.0.1:12345
- --listen-address=127.0.0.1:23456
```

The redirect URL defaults to `http://localhost` with the listening port.
You can override the redirect URL.

```yaml
- --oidc-redirect-url=http://127.0.0.1:8000/
- --oidc-redirect-url=http://your-local-hostname:8000/
```

You can specify a certificate for the local webserver if HTTPS is required by your identity provider.

```yaml
- --local-server-cert=localhost.crt
- --local-server-key=localhost.key
```

You can add extra parameters to the authentication request.

```yaml
- --oidc-auth-request-extra-params=ttl=86400
```

When authentication completed, kubelogin shows a message to close the browser.
You can change the URL to show after authentication.

```yaml
- --open-url-after-authentication=https://example.com/success.html
```

If you encounter a problem with the browser, you can change the browser command or skip opening the browser.

```yaml
# Change the browser command
- --browser-command=google-chrome
# Do not open the browser
- --skip-open-browser
```

### Authorization code flow with a keyboard

If you cannot access the browser, instead use the authorization code flow with a keyboard.

```yaml
- --grant-type=authcode-keyboard
```

You need to explicitly set the redirect URL.

```yaml
- --oidc-redirect-url=urn:ietf:wg:oauth:2.0:oob
- --oidc-redirect-url=http://localhost
```

Kubelogin will show the URL and prompt.
Open the URL in the browser and then copy the code shown.

```
% kubectl get pods
Open https://accounts.google.com/o/oauth2/v2/auth?access_type=offline&client_id=...
Enter code: YOUR_CODE
```

You can add extra parameters to the authentication request.

```yaml
- --oidc-auth-request-extra-params=ttl=86400
```

### Device authorization grant

Kubelogin performs the [device authorization grant](https://tools.ietf.org/html/rfc8628) when `--grant-type=device-code` is set.

```yaml
- --grant-type=device-code
```

It automatically opens the browser.
If the provider returns the `verification_uri_complete` parameter, you don't need to enter the code.
Otherwise, you need to enter the code shown.

If you encounter a problem with the browser, you can change the browser command or skip opening the browser.

```yaml
# Change the browser command
- --browser-command=google-chrome
# Do not open the browser
- --skip-open-browser
```

### Resource owner password credentials grant

Kubelogin performs the resource owner password credentials grant
when `--grant-type=password` or `--username` is set.

Note that most OIDC providers do not support this grant.
Keycloak supports this grant but you need to explicitly enable the "Direct Access Grants" feature in the client settings.

You can set the username and password.

```yaml
- --username=USERNAME
- --password=PASSWORD
```

If the password is not set, kubelogin will show the prompt for the password.

```yaml
- --username=USERNAME
```

```
% kubectl get pods
Password:
```

If the username is not set, kubelogin will show the prompt for the username and password.

```yaml
- --grant-type=password
```

```
% kubectl get pods
Username: foo
Password:
```

### Client Credentials Flow

Kubelogin performs the [OAuth 2.0 client credentials flow](https://datatracker.ietf.org/doc/html/rfc6749#section-1.3.4) when `--grant-type=client-credentials` is set.

```yaml
- --grant-type=client-credentials
```

Per specification, this flow only returns authorization tokens.

## Run in Docker

You can run [the Docker image](https://ghcr.io/int128/kubelogin) instead of the binary.
The kubeconfig looks like:

```yaml
users:
  - name: oidc
    user:
      exec:
        apiVersion: client.authentication.k8s.io/v1
        command: docker
        args:
          - run
          - --rm
          - -v
          - /tmp/.token-cache:/.token-cache
          - -p
          - 8000:8000
          - ghcr.io/int128/kubelogin
          - get-token
          - --token-cache-dir=/.token-cache
          - --listen-address=0.0.0.0:8000
          - --oidc-issuer-url=ISSUER_URL
          - --oidc-client-id=YOUR_CLIENT_ID
          - --oidc-client-secret=YOUR_CLIENT_SECRET
```

Known limitations:

- It cannot open the browser automatically.
- The container port and listen port must be equal for consistency of the redirect URI.
