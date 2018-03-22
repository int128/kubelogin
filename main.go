package main

import (
	"log"

	"k8s.io/client-go/tools/clientcmd/api"
)

func main() {
	kubeConfigPath, err := FindKubeConfig()
	if err != nil {
		log.Fatal(err)
	}

	log.Printf("Reading config from %s", kubeConfigPath)
	kubeConfig, err := ReadKubeConfig(kubeConfigPath)
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("Using current context: %s", kubeConfig.CurrentContext)

	authInfo := GetCurrentAuthInfo(*kubeConfig)
	if authInfo == nil {
		log.Fatal("Could not find the current user")
	}
	authProvider := authInfo.AuthProvider
	if authProvider == nil {
		log.Fatal("auth-provider is not set in the config")
	}

	switch authProvider.Name {
	case "oidc":
		if err := mutateConfigWithOIDC(authProvider); err != nil {
			log.Fatal(err)
		}
		WriteKubeConfig(*kubeConfig, kubeConfigPath)
		log.Printf("Updated %s", kubeConfigPath)

	default:
		log.Fatalf("Currently auth-provider `%s` is not supported", authProvider.Name)
	}
}

func mutateConfigWithOIDC(authProvider *api.AuthProviderConfig) error {
	issuer := authProvider.Config["idp-issuer-url"]
	clientID := authProvider.Config["client-id"]
	clientSecret := authProvider.Config["client-secret"]
	log.Printf("Using issuer: %s", issuer)
	log.Printf("Using client ID: %s", clientID)
	oidcToken, err := GetOIDCToken(issuer, clientID, clientSecret)
	if err != nil {
		return err
	}
	authProvider.Config["id-token"] = oidcToken.IDToken
	authProvider.Config["refresh-token"] = oidcToken.RefreshToken
	return nil
}
