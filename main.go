package main

import (
	"log"

	"github.com/int128/kubelogin/kubeconfig"
)

func main() {
	path, err := kubeconfig.Find()
	if err != nil {
		log.Fatalf("Could not find kubeconfig: %s", err)
	}
	log.Printf("Reading %s", path)
	cfg, err := kubeconfig.Load(path)
	if err != nil {
		log.Fatalf("Could not load kubeconfig: %s", err)
	}
	log.Printf("Using current-context: %s", cfg.CurrentContext)
	authInfo := kubeconfig.FindCurrentAuthInfo(cfg)
	if authInfo == nil {
		log.Fatalf("Could not find the current-context: %s", cfg.CurrentContext)
	}
	provider, err := kubeconfig.ToOIDCAuthProviderConfig(authInfo)
	if err != nil {
		log.Fatalf("Could not find the OIDC auth-provider: %s", err)
	}
	token, err := GetOIDCToken(provider.IDPIssuerURL(), provider.ClientID(), provider.ClientSecret())
	if err != nil {
		log.Fatalf("OIDC authentication error: %s", err)
	}

	provider.SetIDToken(token.IDToken)
	provider.SetRefreshToken(token.RefreshToken)
	kubeconfig.Write(cfg, path)
	log.Printf("Updated %s", path)
}
