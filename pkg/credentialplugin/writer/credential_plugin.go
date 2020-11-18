// Package writer provides a writer for a credential plugin.
package writer

import (
	"encoding/json"

	"github.com/google/wire"
	"github.com/int128/kubelogin/pkg/adaptors/stdio"
	"github.com/int128/kubelogin/pkg/credentialplugin"
	"golang.org/x/xerrors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	clientauthenticationv1beta1 "k8s.io/client-go/pkg/apis/clientauthentication/v1beta1"
)

//go:generate mockgen -destination mock_writer/mock_writer.go github.com/int128/kubelogin/pkg/credentialplugin/writer Interface

var Set = wire.NewSet(
	wire.Struct(new(Writer), "*"),
	wire.Bind(new(Interface), new(*Writer)),
)

type Interface interface {
	Write(out credentialplugin.Output) error
}

type Writer struct {
	Stdout stdio.Stdout
}

// Write writes the ExecCredential to standard output for kubectl.
func (w *Writer) Write(out credentialplugin.Output) error {
	ec := &clientauthenticationv1beta1.ExecCredential{
		TypeMeta: metav1.TypeMeta{
			APIVersion: "client.authentication.k8s.io/v1beta1",
			Kind:       "ExecCredential",
		},
		Status: &clientauthenticationv1beta1.ExecCredentialStatus{
			Token:               out.Token,
			ExpirationTimestamp: &metav1.Time{Time: out.Expiry},
		},
	}
	e := json.NewEncoder(w.Stdout)
	if err := e.Encode(ec); err != nil {
		return xerrors.Errorf("could not write the ExecCredential: %w", err)
	}
	return nil
}
