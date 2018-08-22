package cli

import (
	"context"
	"crypto/tls"
	"fmt"
	"log"
	"net/http"

	"github.com/int128/kubelogin/auth"
	"github.com/int128/kubelogin/kubeconfig"
	flags "github.com/jessevdk/go-flags"
	homedir "github.com/mitchellh/go-homedir"
	"golang.org/x/oauth2"
)

// Parse parses command line arguments and returns a CLI instance.
func Parse(args []string) (*CLI, error) {
	var cli CLI
	parser := flags.NewParser(&cli, flags.HelpFlag)
	args, err := parser.Parse()
	if err != nil {
		return nil, err
	}
	if len(args) > 0 {
		return nil, fmt.Errorf("Too many argument")
	}
	return &cli, nil
}

// CLI represents an interface of this command.
type CLI struct {
	KubeConfig    string `long:"kubeconfig" default:"~/.kube/config" env:"KUBECONFIG" description:"Path to the kubeconfig file"`
	SkipTLSVerify bool   `long:"insecure-skip-tls-verify" env:"KUBELOGIN_INSECURE_SKIP_TLS_VERIFY" description:"If set, the server's certificate will not be checked for validity. This will make your HTTPS connections insecure"`
	// CertificateAuthority string `long:"certificate-authority" env:"KUBELOGIN_CERTIFICATE_AUTHORITY" description:"Path to a cert file for the certificate authority"`
}

// ExpandKubeConfig returns an expanded KubeConfig path.
func (c *CLI) ExpandKubeConfig() (string, error) {
	d, err := homedir.Expand(c.KubeConfig)
	if err != nil {
		return "", fmt.Errorf("Could not expand %s", c.KubeConfig)
	}
	return d, nil
}

// Run performs this command.
func (c *CLI) Run() error {
	path, err := c.ExpandKubeConfig()
	if err != nil {
		return err
	}
	log.Printf("Reading %s", path)
	cfg, err := kubeconfig.Load(path)
	if err != nil {
		return fmt.Errorf("Could not load kubeconfig: %s", err)
	}
	log.Printf("Using current context: %s", cfg.CurrentContext)
	authInfo := kubeconfig.FindCurrentAuthInfo(cfg)
	if authInfo == nil {
		return fmt.Errorf("Could not find current context: %s", cfg.CurrentContext)
	}
	authProvider, err := kubeconfig.ToOIDCAuthProviderConfig(authInfo)
	if err != nil {
		return fmt.Errorf("Could not find auth-provider: %s", err)
	}

	client := &http.Client{Transport: &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: c.SkipTLSVerify},
	}}
	ctx := context.Background()
	ctx = context.WithValue(ctx, oauth2.HTTPClient, client)
	token, err := auth.GetTokenSet(ctx, authProvider.IDPIssuerURL(), authProvider.ClientID(), authProvider.ClientSecret())
	if err != nil {
		return fmt.Errorf("Authentication error: %s", err)
	}

	authProvider.SetIDToken(token.IDToken)
	authProvider.SetRefreshToken(token.RefreshToken)
	kubeconfig.Write(cfg, path)
	log.Printf("Updated %s", path)
	return nil
}
