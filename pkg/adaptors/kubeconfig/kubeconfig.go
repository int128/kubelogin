package kubeconfig

import (
	"github.com/google/wire"
	"github.com/int128/kubelogin/pkg/adaptors"
)

// Set provides an implementation and interface for Kubeconfig.
var Set = wire.NewSet(
	wire.Struct(new(Kubeconfig), "*"),
	wire.Bind(new(adaptors.Kubeconfig), new(*Kubeconfig)),
)

type Kubeconfig struct{}
