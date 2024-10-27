// Package writer provides a writer for the credential plugin.
package writer

import (
	"encoding/json"
	"fmt"

	"github.com/google/wire"
	"github.com/int128/kubelogin/pkg/credentialplugin"
	"github.com/int128/kubelogin/pkg/infrastructure/stdio"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	clientauthenticationv1 "k8s.io/client-go/pkg/apis/clientauthentication/v1"
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
	execCredential, err := generateExecCredential(out)
	if err != nil {
		return fmt.Errorf("generate ExecCredential: %w", err)
	}
	if err := json.NewEncoder(w.Stdout).Encode(execCredential); err != nil {
		return fmt.Errorf("write ExecCredential: %w", err)
	}
	return nil
}

func generateExecCredential(out credentialplugin.Output) (any, error) {
	switch out.ClientAuthenticationAPIVersion {
	// Default to v1beta1 if KUBERNETES_EXEC_INFO is not available
	case clientauthenticationv1beta1.SchemeGroupVersion.String(), "":
		return &clientauthenticationv1beta1.ExecCredential{
			TypeMeta: metav1.TypeMeta{
				APIVersion: clientauthenticationv1beta1.SchemeGroupVersion.String(),
				Kind:       "ExecCredential",
			},
			Status: &clientauthenticationv1beta1.ExecCredentialStatus{
				Token:               out.Token,
				ExpirationTimestamp: &metav1.Time{Time: out.Expiry},
			},
		}, nil

	case clientauthenticationv1.SchemeGroupVersion.String():
		return &clientauthenticationv1.ExecCredential{
			TypeMeta: metav1.TypeMeta{
				APIVersion: clientauthenticationv1.SchemeGroupVersion.String(),
				Kind:       "ExecCredential",
			},
			Status: &clientauthenticationv1.ExecCredentialStatus{
				Token:               out.Token,
				ExpirationTimestamp: &metav1.Time{Time: out.Expiry},
			},
		}, nil

	default:
		return nil, fmt.Errorf("unknown apiVersion: %s", out.ClientAuthenticationAPIVersion)
	}
}
