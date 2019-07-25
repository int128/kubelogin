# Team on-boarding

## kops

Export the kubeconfig.

```sh
KUBECONFIG=.kubeconfig kops export kubecfg hello.k8s.local
```

Remove the `admin` access from the kubeconfig.
It should look as like:

```yaml
apiVersion: v1
kind: Config
clusters:
  - cluster:
      certificate-authority-data: LS...
      server: https://api.hello.k8s.example.com
      name: hello.k8s.local
contexts:
- context:
    cluster: hello.k8s.local
    user: hello.k8s.local
  name: hello.k8s.local
current-context: hello.k8s.local
preferences: {}
users:
- name: hello.k8s.local
  user:
    exec:
      apiVersion: client.authentication.k8s.io/v1beta1
      command: kubelogin
      args:
      - get-token
      - --oidc-issuer-url=https://keycloak.example.com/auth/realms/YOUR_REALM
      - --oidc-client-id=YOUR_CLIENT_ID
      - --oidc-client-secret=YOUR_CLIENT_SECRET
```

You can share the kubeconfig to your team members for on-boarding.
