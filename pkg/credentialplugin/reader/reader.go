// Package reader provides a loader for the credential plugin.
package reader

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/google/wire"
	"github.com/int128/kubelogin/pkg/credentialplugin"
	"k8s.io/client-go/pkg/apis/clientauthentication"
)

var Set = wire.NewSet(
	wire.Struct(new(Reader), "*"),
	wire.Bind(new(Interface), new(*Reader)),
)

type Interface interface {
	Read() (credentialplugin.Input, error)
}

type Reader struct{}

// Read parses the environment variable KUBERNETES_EXEC_INFO.
// If the environment variable is not given by kubectl, Read returns a zero value.
func (r Reader) Read() (credentialplugin.Input, error) {
	execInfo := os.Getenv("KUBERNETES_EXEC_INFO")
	if execInfo == "" {
		return credentialplugin.Input{}, nil
	}
	var execCredential clientauthentication.ExecCredential
	if err := json.Unmarshal([]byte(execInfo), &execCredential); err != nil {
		return credentialplugin.Input{}, fmt.Errorf("invalid KUBERNETES_EXEC_INFO: %w", err)
	}
	return credentialplugin.Input{
		ClientAuthenticationAPIVersion: execCredential.APIVersion,
	}, nil
}
