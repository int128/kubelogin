package setup

import (
	"context"
	"fmt"
	"strings"
	"text/template"

	"github.com/int128/kubelogin/pkg/usecases/authentication"
	"golang.org/x/xerrors"
)

var stage2Tpl = template.Must(template.New("").Parse(`
## 3. Bind a role

Run the following command:

	kubectl apply -f - <<-EOF
	kind: ClusterRoleBinding
	apiVersion: rbac.authorization.k8s.io/v1
	metadata:
	  name: oidc-cluster-admin
	roleRef:
	  apiGroup: rbac.authorization.k8s.io
	  kind: ClusterRole
	  name: cluster-admin
	subjects:
	- kind: User
	  name: {{ .IssuerURL }}#{{ .Subject }}
	EOF

## 4. Set up the Kubernetes API server

Add the following options to the kube-apiserver:

	--oidc-issuer-url={{ .IssuerURL }}
	--oidc-client-id={{ .ClientID }}

## 5. Set up the kubeconfig

Add the following user to the kubeconfig:

	users:
	- name: google
	  user:
	    exec:
	      apiVersion: client.authentication.k8s.io/v1beta1
	      command: kubectl
	      args:
	      - oidc-login
	      - get-token
{{- range .Args }}
	      - {{ . }}
{{- end }}

Run kubectl and verify cluster access.
`))

type stage2Vars struct {
	IssuerURL string
	ClientID  string
	Args      []string
	Subject   string
}

// Stage2Input represents an input DTO of the stage2.
type Stage2Input struct {
	IssuerURL      string
	ClientID       string
	ClientSecret   string
	ExtraScopes    []string // optional
	CACertFilename string   // If set, use the CA cert
	SkipTLSVerify  bool
	ListenPortArgs []int // non-nil if set by the command arg

	AuthCodeOption *authentication.AuthCodeOption
	ROPCOption     *authentication.ROPCOption
}

func (u *Setup) DoStage2(ctx context.Context, in Stage2Input) error {
	u.Logger.Printf(`## 2. Verify authentication`)
	certPool := u.CertPoolFactory.New()
	if in.CACertFilename != "" {
		if err := certPool.AddFile(in.CACertFilename); err != nil {
			return xerrors.Errorf("could not load the certificate: %w", err)
		}
	}
	out, err := u.Authentication.Do(ctx, authentication.Input{
		IssuerURL:      in.IssuerURL,
		ClientID:       in.ClientID,
		ClientSecret:   in.ClientSecret,
		ExtraScopes:    in.ExtraScopes,
		CertPool:       certPool,
		SkipTLSVerify:  in.SkipTLSVerify,
		AuthCodeOption: in.AuthCodeOption,
		ROPCOption:     in.ROPCOption,
	})
	if err != nil {
		return xerrors.Errorf("error while authentication: %w", err)
	}
	u.Logger.Printf("You got the following claims in the token:")
	for k, v := range out.IDTokenClaims {
		u.Logger.Printf("\t%s=%s", k, v)
	}

	v := stage2Vars{
		IssuerURL: in.IssuerURL,
		ClientID:  in.ClientID,
		Args:      makeCredentialPluginArgs(in),
		Subject:   out.IDTokenSubject,
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
	if in.SkipTLSVerify {
		args = append(args, "--insecure-skip-tls-verify")
	}

	if in.AuthCodeOption != nil {
		if in.AuthCodeOption.SkipOpenBrowser {
			args = append(args, "--skip-open-browser")
		}
	}
	for _, port := range in.ListenPortArgs {
		args = append(args, fmt.Sprintf("--listen-port=%d", port))
	}
	if in.ROPCOption != nil {
		if in.ROPCOption.Username != "" {
			args = append(args, "--username="+in.ROPCOption.Username)
		}
	}
	return args
}
