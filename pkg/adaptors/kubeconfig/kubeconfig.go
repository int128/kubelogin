package kubeconfig

import (
	"github.com/google/wire"
	"github.com/pipedrive/kubelogin/pkg/adaptors/logger"
)

//go:generate mockgen -destination mock_kubeconfig/mock_kubeconfig.go github.com/int128/kubelogin/pkg/adaptors/kubeconfig Interface

// Set provides an implementation and interface for Kubeconfig.
var Set = wire.NewSet(
	wire.Struct(new(Kubeconfig), "*"),
	wire.Bind(new(Interface), new(*Kubeconfig)),
)

type Interface interface {
	GetCurrentAuthProvider(explicitFilename string, contextName ContextName, userName UserName) (*AuthProvider, error)
	UpdateAuthProvider(auth *AuthProvider) error
}

// ContextName represents name of a context.
type ContextName string

// UserName represents name of a user.
type UserName string

// AuthProvider represents the authentication provider,
// i.e. context, user and auth-provider in a kubeconfig.
type AuthProvider struct {
	LocationOfOrigin            string      // Path to the kubeconfig file which contains the user
	UserName                    UserName    // User name
	ContextName                 ContextName // (optional) Context name
	IDPIssuerURL                string      // idp-issuer-url
	ClientID                    string      // client-id
	ClientSecret                string      // (optional) client-secret
	IDPCertificateAuthority     string      // (optional) idp-certificate-authority
	IDPCertificateAuthorityData string      // (optional) idp-certificate-authority-data
	ExtraScopes                 []string    // (optional) extra-scopes
	IDToken                     string      // (optional) id-token
	RefreshToken                string      // (optional) refresh-token
}

type Kubeconfig struct {
	Logger logger.Interface
}
