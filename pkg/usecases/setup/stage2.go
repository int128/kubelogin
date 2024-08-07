package setup

import (
	"context"
	"fmt"
	"path/filepath"
	"strings"
	"text/template"

	"github.com/int128/kubelogin/pkg/oidc"
	"github.com/int128/kubelogin/pkg/tlsclientconfig"
	"github.com/int128/kubelogin/pkg/usecases/authentication"
)

var stage2Tpl = template.Must(template.New("").Parse(`
## 2. Verify authentication

You got a token with the following claims:

{{ .IDTokenPrettyJSON }}

## 3. Bind a cluster role

Run the following command:

	kubectl create clusterrolebinding oidc-cluster-admin --clusterrole=cluster-admin --user='{{ .IssuerURL }}#{{ .Subject }}'

## 4. Set up the Kubernetes API server

Add the following options to the kube-apiserver:

	--oidc-issuer-url={{ .IssuerURL }}
	--oidc-client-id={{ .ClientID }}

## 5. Set up the kubeconfig

Run the following command:

	kubectl config set-credentials oidc \
	  --exec-api-version=client.authentication.k8s.io/v1beta1 \
	  --exec-command=kubectl \
	  --exec-arg=oidc-login \
	  --exec-arg=get-token \
{{- range $index, $arg := .Args }}
	  {{- if $index}} \{{end}}
	  --exec-arg={{ $arg }}
{{- end }}

## 6. Verify cluster access

Make sure you can access the Kubernetes cluster.

	kubectl --user=oidc get nodes

You can switch the default context to oidc.

	kubectl config set-context --current --user=oidc

You can share the kubeconfig to your team members for on-boarding.
`))

type stage2Vars struct {
	IDTokenPrettyJSON string
	IssuerURL         string
	ClientID          string
	Args              []string
	Subject           string
}

// Stage2Input represents an input DTO of the stage2.
type Stage2Input struct {
	IssuerURL         string
	ClientID          string
	ClientSecret      string
	ExtraScopes       []string // optional
	UsePKCE           bool     // optional
	UseAccessToken    bool     // optional
	ListenAddressArgs []string // non-nil if set by the command arg
	GrantOptionSet    authentication.GrantOptionSet
	TLSClientConfig   tlsclientconfig.Config
}

func (u *Setup) DoStage2(ctx context.Context, in Stage2Input) error {
	u.Logger.Printf("authentication in progress...")
	out, err := u.Authentication.Do(ctx, authentication.Input{
		Provider: oidc.Provider{
			IssuerURL:    in.IssuerURL,
			ClientID:     in.ClientID,
			ClientSecret: in.ClientSecret,
			ExtraScopes:  in.ExtraScopes,
			UsePKCE:      in.UsePKCE,
		},
		GrantOptionSet:  in.GrantOptionSet,
		TLSClientConfig: in.TLSClientConfig,
		UseAccessToken:  in.UseAccessToken,
	})
	if err != nil {
		return fmt.Errorf("authentication error: %w", err)
	}
	idTokenClaims, err := out.TokenSet.DecodeWithoutVerify()
	if err != nil {
		return fmt.Errorf("you got an invalid token: %w", err)
	}

	v := stage2Vars{
		IDTokenPrettyJSON: idTokenClaims.Pretty,
		IssuerURL:         in.IssuerURL,
		ClientID:          in.ClientID,
		Args:              makeCredentialPluginArgs(in),
		Subject:           idTokenClaims.Subject,
	}
	var b strings.Builder
	if err := stage2Tpl.Execute(&b, &v); err != nil {
		return fmt.Errorf("could not render the template: %w", err)
	}
	u.Logger.Printf(b.String())
	return nil
}

func makeCredentialPluginArgs(in Stage2Input) []string {
	var args []string
	args = append(args, "--oidc-issuer-url="+in.IssuerURL)
	args = append(args, "--oidc-client-id="+in.ClientID)
	if in.ClientSecret != "" {
		args = append(args, "--oidc-client-secret="+in.ClientSecret)
	}
	for _, extraScope := range in.ExtraScopes {
		args = append(args, "--oidc-extra-scope="+extraScope)
	}
	if in.UsePKCE {
		args = append(args, "--oidc-use-pkce")
	}
	if in.UseAccessToken {
		args = append(args, "--oidc-use-access-token")
	}
	for _, f := range in.TLSClientConfig.CACertFilename {
		args = append(args, "--certificate-authority="+f)
	}
	for _, d := range in.TLSClientConfig.CACertData {
		args = append(args, "--certificate-authority-data="+d)
	}
	if in.TLSClientConfig.SkipTLSVerify {
		args = append(args, "--insecure-skip-tls-verify")
	}

	if in.GrantOptionSet.AuthCodeBrowserOption != nil {
		if in.GrantOptionSet.AuthCodeBrowserOption.SkipOpenBrowser {
			args = append(args, "--skip-open-browser")
		}
		if in.GrantOptionSet.AuthCodeBrowserOption.BrowserCommand != "" {
			args = append(args, "--browser-command="+in.GrantOptionSet.AuthCodeBrowserOption.BrowserCommand)
		}
		if in.GrantOptionSet.AuthCodeBrowserOption.LocalServerCertFile != "" {
			// Resolve the absolute path for the cert files so the user doesn't have to know
			// to use one when running setup.
			certpath, err := filepath.Abs(in.GrantOptionSet.AuthCodeBrowserOption.LocalServerCertFile)
			if err != nil {
				panic(err)
			}
			keypath, err := filepath.Abs(in.GrantOptionSet.AuthCodeBrowserOption.LocalServerKeyFile)
			if err != nil {
				panic(err)
			}
			args = append(args, "--local-server-cert="+certpath)
			args = append(args, "--local-server-key="+keypath)
		}
	}
	for _, l := range in.ListenAddressArgs {
		args = append(args, "--listen-address="+l)
	}
	if in.GrantOptionSet.ROPCOption != nil {
		if in.GrantOptionSet.ROPCOption.Username != "" {
			args = append(args, "--username="+in.GrantOptionSet.ROPCOption.Username)
		}
	}
	return args
}
