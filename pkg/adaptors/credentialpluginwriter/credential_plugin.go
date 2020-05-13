// Package credentialpluginwriter provides a writer for a credential plugin.
package credentialpluginwriter

import (
	"encoding/json"
	"time"

	"github.com/google/wire"
	"github.com/int128/kubelogin/pkg/adaptors/stdio"
	"golang.org/x/xerrors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	clientauthenticationv1beta1 "k8s.io/client-go/pkg/apis/clientauthentication/v1beta1"
)

//go:generate mockgen -destination mock_credentialpluginwriter/mock_credentialpluginwriter.go github.com/int128/kubelogin/pkg/adaptors/credentialpluginwriter Interface

var Set = wire.NewSet(
	wire.Struct(new(Writer), "*"),
	wire.Bind(new(Interface), new(*Writer)),
)

type Interface interface {
	Write(out Output) error
}

// Output represents an output object of the credential plugin.
type Output struct {
	Token  string
	Expiry time.Time
}

type Writer struct {
	Stdout stdio.Stdout
}

// Write writes the ExecCredential to standard output for kubectl.
func (w *Writer) Write(out Output) error {
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
