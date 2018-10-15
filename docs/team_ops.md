# Team Operation

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
    auth-provider:
      name: oidc
      config:
        client-id: YOUR_CLIEND_ID
        client-secret: YOUR_CLIENT_SECRET
        idp-issuer-url: YOUR_ISSUER
```

You can share the kubeconfig to your team members for easy onboarding.
