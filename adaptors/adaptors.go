// Package adaptors provides bridge between use-cases and external infrastructure.
package adaptors

import (
	"github.com/google/wire"
	adaptors "github.com/int128/kubelogin/adaptors/interfaces"
)

var Set = wire.NewSet(
	Cmd{},
	HTTP{},
	KubeConfig{},
	OIDC{},
	wire.Bind((*adaptors.Cmd)(nil), (*Cmd)(nil)),
	wire.Bind((*adaptors.HTTP)(nil), (*HTTP)(nil)),
	wire.Bind((*adaptors.KubeConfig)(nil), (*KubeConfig)(nil)),
	wire.Bind((*adaptors.OIDC)(nil), (*OIDC)(nil)),
)
