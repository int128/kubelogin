# Usage

Kubelogin supports the following options:

```
Usage:
  kubelogin get-token [flags]

Flags:
      --oidc-issuer-url string                          Issuer URL of the provider (mandatory)
      --oidc-client-id string                           Client ID of the provider (mandatory)
      --oidc-client-secret string                       Client secret of the provider
      --oidc-extra-scope strings                        Scopes to request to the provider
      --oidc-use-pkce                                   Force PKCE usage
      --token-cache-dir string                          Path to a directory for token cache (default "~/.kube/cache/oidc-login")
      --certificate-authority stringArray               Path to a cert file for the certificate authority
      --certificate-authority-data stringArray          Base64 encoded cert for the certificate authority
      --insecure-skip-tls-verify                        If set, the server's certificate will not be checked for validity. This will make your HTTPS connections insecure
      --tls-renegotiation-once                          If set, allow a remote server to request renegotiation once per connection
      --tls-renegotiation-freely                        If set, allow a remote server to repeatedly request renegotiation
      --grant-type string                               Authorization grant type to use. One of (auto|authcode|authcode-keyboard|password) (default "auto")
      --listen-address strings                          [authcode] Address to bind to the local server. If multiple addresses are set, it will try binding in order (default [127.0.0.1:8000,127.0.0.1:18000])
      --skip-open-browser                               [authcode] Do not open the browser automatically
      --browser-command string                          [authcode] Command to open the browser
      --authentication-timeout-sec int                  [authcode] Timeout of authentication in seconds (default 180)
      --local-server-cert string                        [authcode] Certificate path for the local server
      --local-server-key string                         [authcode] Certificate key path for the local server
      --open-url-after-authentication string            [authcode] If set, open the URL in the browser after authentication
      --oidc-redirect-url-hostname string               [authcode] Hostname of the redirect URL (default "localhost")
      --oidc-auth-request-extra-params stringToString   [authcode, authcode-keyboard] Extra query parameters to send with an authentication request (default [])
      --username string                                 [password] Username for resource owner password credentials grant
      --password string                                 [password] Password for resource owner password credentials grant
  -h, --help                                            help for get-token

Global Flags:
      --add_dir_header                   If true, adds the file directory to the header of the log messages
      --alsologtostderr                  log to standard error as well as files
      --log_backtrace_at traceLocation   when logging hits line file:N, emit a stack trace (default :0)
      --log_dir string                   If non-empty, write log files in this directory
      --log_file string                  If non-empty, use this log file
      --log_file_max_size uint           Defines the maximum size a log file can grow to. Unit is megabytes. If the value is 0, the maximum file size is unlimited. (default 1800)
      --logtostderr                      log to standard error instead of files (default true)
      --one_output                       If true, only write logs to their native severity level (vs also writing to each lower severity level)
      --skip_headers                     If true, avoid header prefixes in the log messages
      --skip_log_headers                 If true, avoid headers when opening log files
      --stderrthreshold severity         logs at or above this threshold go to stderr (default 2)
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

### CA certificate

You can use your self-signed certificate for the provider.

```yaml
      - --certificate-authority=/home/user/.kube/keycloak-ca.pem
      - --certificate-authority-data=LS0t...
```

### HTTP proxy

You can set the following environment variables if you are behind a proxy: `HTTP_PROXY`, `HTTPS_PROXY` and `NO_PROXY`.
See also [net/http#ProxyFromEnvironment](https://golang.org/pkg/net/http/#ProxyFromEnvironment).

### Home directory expansion

If a value in the following options begins with a tilde character `~`, it is expanded to the home directory.

- `--certificate-authority`
- `--local-server-cert`
- `--local-server-key`
- `--token-cache-dir`


## Authentication flows

Kubelogin support the following flows:

- Authorization code flow
- Authorization code flow with a keyboard
- Resource owner password credentials grant flow

### Authorization code flow

Kubelogin performs the authorization code flow by default.

It starts the local server at port 8000 or 18000 by default.
You need to register the following redirect URIs to the provider:

- `http://localhost:8000`
- `http://localhost:18000` (used if port 8000 is already in use)

You can change the listening address.

```yaml
      - --listen-address=127.0.0.1:12345
      - --listen-address=127.0.0.1:23456
```

You can specify a certificate for the local webserver if HTTPS is required by your identity provider.

```yaml
      - --local-server-cert=localhost.crt
      - --local-server-key=localhost.key
```

You can change the hostname of redirect URI from the default value `localhost`.

```yaml
      - --oidc-redirect-url-hostname=127.0.0.1
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

You can skip opening the browser if you encounter some environment problem.

```yaml
      - --skip-open-browser
```

For Linux users, you change the default browser by `BROWSER` environment variable.

### Authorization code flow with a keyboard

If you cannot access the browser, instead use the authorization code flow with a keyboard.

```yaml
      - --grant-type=authcode-keyboard
```

Kubelogin will show the URL and prompt.
Open the URL in the browser and then copy the code shown.

```
% kubectl get pods
Open https://accounts.google.com/o/oauth2/v2/auth?access_type=offline&client_id=...
Enter code: YOUR_CODE
```

Note that this flow uses the redirect URI `urn:ietf:wg:oauth:2.0:oob` and some OIDC providers do not support it.

You can add extra parameters to the authentication request.

```yaml
      - --oidc-auth-request-extra-params=ttl=86400
```

### Resource owner password credentials grant flow

Kubelogin performs the resource owner password credentials grant flow
when `--grant-type=password` or `--username` is set.

Note that most OIDC providers do not support this flow.
Keycloak supports this flow but you need to explicitly enable the "Direct Access Grants" feature in the client settings.

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

## Run in Docker

You can run [the Docker image](https://ghcr.io/int128/kubelogin) instead of the binary.
The kubeconfig looks like:

```yaml
users:
- name: oidc
  user:
    exec:
      apiVersion: client.authentication.k8s.io/v1beta1
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
