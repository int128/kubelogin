This setup shows the instruction of Kubernetes OpenID Connect authentication.

You need to set up the OpenID Connect Provider.
Run the following command to authenticate with the OpenID Connect Provider:

```
kubectl oidc-login setup \
  --oidc-issuer-url=ISSUER_URL \
  --oidc-client-id=YOUR_CLIENT_ID
```

See https://github.com/int128/kubelogin for the details.
