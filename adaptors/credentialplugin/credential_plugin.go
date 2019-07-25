// Package credentialplugin provides interaction with kubectl for a credential plugin.
package credentialplugin

import (
	"encoding/json"
	"os"

	"github.com/google/wire"
	"github.com/int128/kubelogin/adaptors"
	"github.com/int128/kubelogin/models/credentialplugin"
	"golang.org/x/xerrors"
	"k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/pkg/apis/clientauthentication/v1beta1"
)

var Set = wire.NewSet(
	wire.Struct(new(Interaction), "*"),
	wire.Bind(new(adaptors.CredentialPluginInteraction), new(*Interaction)),
)

type Interaction struct{}

// Write writes the ExecCredential to standard output for kubectl.
func (*Interaction) Write(out credentialplugin.Output) error {
	ec := &v1beta1.ExecCredential{
		TypeMeta: v1.TypeMeta{
			APIVersion: "client.authentication.k8s.io/v1beta1",
			Kind:       "ExecCredential",
		},
		Status: &v1beta1.ExecCredentialStatus{
			Token:               out.Token,
			ExpirationTimestamp: &v1.Time{Time: out.Expiry},
		},
	}
	e := json.NewEncoder(os.Stdout)
	if err := e.Encode(ec); err != nil {
		return xerrors.Errorf("could not write the ExecCredential: %w", err)
	}
	return nil
}
