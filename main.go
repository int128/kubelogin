package main

import (
	"context"
	"crypto/tls"
	"fmt"
	"log"
	"net/http"

	"github.com/int128/kubelogin/authn"
	"github.com/int128/kubelogin/kubeconfig"
	flags "github.com/jessevdk/go-flags"
	homedir "github.com/mitchellh/go-homedir"
	"golang.org/x/oauth2"
)

type options struct {
	KubeConfig    string `long:"kubeconfig" default:"~/.kube/config" env:"KUBECONFIG" description:"Path to the kubeconfig file"`
	SkipTLSVerify bool   `long:"insecure-skip-tls-verify" env:"KUBELOGIN_INSECURE_SKIP_TLS_VERIFY" description:"If set, the server's certificate will not be checked for validity. This will make your HTTPS connections insecure"`
	// CertificateAuthority string `long:"certificate-authority" env:"KUBELOGIN_CERTIFICATE_AUTHORITY" description:"Path to a cert file for the certificate authority"`
}

func (o *options) ExpandKubeConfig() (string, error) {
	d, err := homedir.Expand(o.KubeConfig)
	if err != nil {
		return "", fmt.Errorf("Could not expand %s", o.KubeConfig)
	}
	return d, nil
}

func parseOptions() (*options, error) {
	var o options
	parser := flags.NewParser(&o, flags.HelpFlag)
	args, err := parser.Parse()
	if err != nil {
		return nil, err
	}
	if len(args) > 0 {
		return nil, fmt.Errorf("Too many argument")
	}
	return &o, nil
}

func main() {
	opts, err := parseOptions()
	if err != nil {
		log.Fatal(err)
	}
	path, err := opts.ExpandKubeConfig()
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("Reading %s", path)
	cfg, err := kubeconfig.Load(path)
	if err != nil {
		log.Fatalf("Could not load kubeconfig: %s", err)
	}
	log.Printf("Using current context: %s", cfg.CurrentContext)
	authInfo := kubeconfig.FindCurrentAuthInfo(cfg)
	if authInfo == nil {
		log.Fatalf("Could not find current context: %s", cfg.CurrentContext)
	}
	authProvider, err := kubeconfig.ToOIDCAuthProviderConfig(authInfo)
	if err != nil {
		log.Fatalf("Could not find auth-provider: %s", err)
	}

	client := &http.Client{Transport: &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: opts.SkipTLSVerify},
	}}
	ctx := context.Background()
	ctx = context.WithValue(ctx, oauth2.HTTPClient, client)
	token, err := authn.GetTokenSet(ctx, authProvider.IDPIssuerURL(), authProvider.ClientID(), authProvider.ClientSecret())
	if err != nil {
		log.Fatalf("Authentication error: %s", err)
	}

	authProvider.SetIDToken(token.IDToken)
	authProvider.SetRefreshToken(token.RefreshToken)
	kubeconfig.Write(cfg, path)
	log.Printf("Updated %s", path)
}
