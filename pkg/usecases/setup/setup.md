## Authenticated with the OpenID Connect Provider

You got the token with the following claims:

```
{{ .IDTokenPrettyJSON }}
```

## Set up the kubeconfig

You can run the following command to set up the kubeconfig:

```
kubectl config set-credentials oidc \
  --exec-api-version=client.authentication.k8s.io/v1 \
  --exec-interactive-mode=Never \
  --exec-command=kubectl \
  --exec-arg=oidc-login \
  --exec-arg=get-token \
{{- range $index, $flag := .Flags }}
  {{- if $index}} \{{end}}
  --exec-arg={{ $flag | quote }}
{{- end }}
```
