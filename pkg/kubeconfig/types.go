package kubeconfig

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
