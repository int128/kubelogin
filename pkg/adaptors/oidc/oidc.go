package oidc

import (
	"github.com/google/wire"
)

//go:generate mockgen -destination mock_oidc/mock_oidc.go github.com/int128/kubelogin/pkg/adaptors/oidc FactoryInterface,Interface,DecoderInterface

// Set provides an implementation and interface for OIDC.
var Set = wire.NewSet(
	wire.Struct(new(Factory), "*"),
	wire.Bind(new(FactoryInterface), new(*Factory)),
	wire.Struct(new(Decoder)),
	wire.Bind(new(DecoderInterface), new(*Decoder)),
)
