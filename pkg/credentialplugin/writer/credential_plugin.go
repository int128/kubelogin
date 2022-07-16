// Package writer provides a writer for a credential plugin.
package writer

import (
	"encoding/json"
	"fmt"

	"github.com/google/wire"
	"github.com/int128/kubelogin/pkg/credentialplugin"
	"github.com/int128/kubelogin/pkg/infrastructure/stdio"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	clientauthenticationv1beta1 "k8s.io/client-go/pkg/apis/clientauthentication/v1beta1"
)

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
		return fmt.Errorf("could not write the ExecCredential: %w", err)
	}
	return nil
}
