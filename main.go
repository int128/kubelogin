package main

import (
	"context"
	"log"

	"github.com/int128/kubelogin/authn"
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
	log.Printf("Using current context: %s", cfg.CurrentContext)
	authInfo := kubeconfig.FindCurrentAuthInfo(cfg)
	if authInfo == nil {
		log.Fatalf("Could not find current context: %s", cfg.CurrentContext)
	}
	authProvider, err := kubeconfig.ToOIDCAuthProviderConfig(authInfo)
	if err != nil {
		log.Fatalf("Could not find auth-provider: %s", err)
	}

	ctx := context.Background()
	token, err := authn.GetTokenSet(ctx, authProvider.IDPIssuerURL(), authProvider.ClientID(), authProvider.ClientSecret())
	if err != nil {
		log.Fatalf("Authentication error: %s", err)
	}

	authProvider.SetIDToken(token.IDToken)
	authProvider.SetRefreshToken(token.RefreshToken)
	kubeconfig.Write(cfg, path)
	log.Printf("Updated %s", path)
}
