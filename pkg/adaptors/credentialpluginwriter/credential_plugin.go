// Package credentialpluginwriter provides a writer for a credential plugin.
package credentialpluginwriter

import (
	"encoding/json"
	"io"
	"os"
	"time"

	"github.com/google/wire"
	"golang.org/x/xerrors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	clientauthenticationv1beta1 "k8s.io/client-go/pkg/apis/clientauthentication/v1beta1"
)

//go:generate mockgen -destination mock_credentialpluginwriter/mock_credentialpluginwriter.go github.com/int128/kubelogin/pkg/adaptors/credentialpluginwriter Interface

var Set = wire.NewSet(
	New,
)

type Interface interface {
	Write(out Output) error
}

// Output represents an output object of the credential plugin.
type Output struct {
	Token  string
	Expiry time.Time
}

// New returns a writer to os.Stdout.
func New() Interface {
	return &writer{writer: os.Stdout}
}

func NewTo(w io.Writer) Interface {
	return &writer{writer: w}
}

type writer struct {
	writer io.Writer
}

// Write writes the ExecCredential to standard output for kubectl.
func (w *writer) Write(out Output) error {
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
	e := json.NewEncoder(w.writer)
	if err := e.Encode(ec); err != nil {
		return xerrors.Errorf("could not write the ExecCredential: %w", err)
	}
	return nil
}
