package setup

const stage1 = `This setup shows the instruction of Kubernetes OpenID Connect authentication.
See also https://github.com/int128/kubelogin.

## 1. Set up the OpenID Connect Provider

Open the OpenID Connect Provider and create a client.

For example, Google Identity Platform:
Open https://console.developers.google.com/apis/credentials and create an OAuth client of "Other" type.
ISSUER is https://accounts.google.com

## 2. Verify authentication

Run the following command to proceed.

	kubectl oidc-login setup \
	  --oidc-issuer-url=ISSUER \
	  --oidc-client-id=YOUR_CLIENT_ID \
	  --oidc-client-secret=YOUR_CLIENT_SECRET

You can set your CA certificate. See also the options by --help.
`

func (u *Setup) DoStage1() {
	u.Logger.Printf(stage1)
}
