package kubeconfig

import (
	"github.com/google/wire"
	"github.com/int128/kubelogin/adaptors"
)

// Set provides an implementation and interface for Kubeconfig.
var Set = wire.NewSet(
	Kubeconfig{},
	wire.Bind((*adaptors.Kubeconfig)(nil), (*Kubeconfig)(nil)),
)

type Kubeconfig struct{}
