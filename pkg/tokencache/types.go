package tokencache

import (
	"github.com/int128/kubelogin/pkg/oidc"
	"github.com/int128/kubelogin/pkg/tlsclientconfig"
)

// Key represents a key of a token cache.
type Key struct {
	Provider        oidc.Provider
	TLSClientConfig tlsclientconfig.Config
	Username        string
}
