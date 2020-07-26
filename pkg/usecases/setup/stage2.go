package setup

import (
	"context"
	"strings"
	"text/template"

	"github.com/int128/kubelogin/pkg/usecases/authentication"
	"golang.org/x/xerrors"
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
{{- range .Args }}
	  --exec-arg={{ . }} \
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
	CACertFilename    string   // optional
	CACertData        string   // optional
	SkipTLSVerify     bool
	ListenAddressArgs []string // non-nil if set by the command arg
	GrantOptionSet    authentication.GrantOptionSet
}

func (u *Setup) DoStage2(ctx context.Context, in Stage2Input) error {
	u.Logger.Printf("authentication in progress...")
	certPool := u.NewCertPool()
	if in.CACertFilename != "" {
		if err := certPool.AddFile(in.CACertFilename); err != nil {
			return xerrors.Errorf("could not load the certificate file: %w", err)
		}
	}
	if in.CACertData != "" {
		if err := certPool.AddBase64Encoded(in.CACertData); err != nil {
			return xerrors.Errorf("could not load the certificate data: %w", err)
		}
	}
	out, err := u.Authentication.Do(ctx, authentication.Input{
		IssuerURL:      in.IssuerURL,
		ClientID:       in.ClientID,
		ClientSecret:   in.ClientSecret,
		ExtraScopes:    in.ExtraScopes,
		CertPool:       certPool,
		SkipTLSVerify:  in.SkipTLSVerify,
		GrantOptionSet: in.GrantOptionSet,
	})
	if err != nil {
		return xerrors.Errorf("authentication error: %w", err)
	}

	v := stage2Vars{
		IDTokenPrettyJSON: out.IDTokenClaims.Pretty,
		IssuerURL:         in.IssuerURL,
		ClientID:          in.ClientID,
		Args:              makeCredentialPluginArgs(in),
		Subject:           out.IDTokenClaims.Subject,
	}
	var b strings.Builder
	if err := stage2Tpl.Execute(&b, &v); err != nil {
		return xerrors.Errorf("could not render the template: %w", err)
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
	if in.CACertFilename != "" {
		args = append(args, "--certificate-authority="+in.CACertFilename)
	}
	if in.CACertData != "" {
		args = append(args, "--certificate-authority-data="+in.CACertData)
	}
	if in.SkipTLSVerify {
		args = append(args, "--insecure-skip-tls-verify")
	}

	if in.GrantOptionSet.AuthCodeBrowserOption != nil {
		if in.GrantOptionSet.AuthCodeBrowserOption.SkipOpenBrowser {
			args = append(args, "--skip-open-browser")
		}
	}
	args = append(args, in.ListenAddressArgs...)
	if in.GrantOptionSet.ROPCOption != nil {
		if in.GrantOptionSet.ROPCOption.Username != "" {
			args = append(args, "--username="+in.GrantOptionSet.ROPCOption.Username)
		}
	}
	return args
}
