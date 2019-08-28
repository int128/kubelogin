package oidc

import (
	"os"

	"github.com/google/wire"
	"github.com/pkg/browser"
)

//go:generate mockgen -destination mock_oidc/mock_oidc.go github.com/int128/kubelogin/pkg/adaptors/oidc FactoryInterface,Interface,DecoderInterface

func init() {
	// In credential plugin mode, some browser launcher writes a message to stdout
	// and it may break the credential json for client-go.
	// This prevents the browser launcher from breaking the credential json.
	browser.Stdout = os.Stderr
}

// Set provides an implementation and interface for OIDC.
var Set = wire.NewSet(
	wire.Struct(new(Factory), "*"),
	wire.Bind(new(FactoryInterface), new(*Factory)),
	wire.Struct(new(Decoder)),
	wire.Bind(new(DecoderInterface), new(*Decoder)),
)
