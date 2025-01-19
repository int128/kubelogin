package reader

import (
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/int128/kubelogin/pkg/credentialplugin"
)

func TestReader_Read(t *testing.T) {
	var reader Reader

	t.Run("KUBERNETES_EXEC_INFO is empty", func(t *testing.T) {
		input, err := reader.Read()
		if err != nil {
			t.Errorf("Read returned error: %v", err)
		}
		want := credentialplugin.Input{}
		if diff := cmp.Diff(want, input); diff != "" {
			t.Errorf("input mismatch (-want +got):\n%s", diff)
		}
	})
	t.Run("KUBERNETES_EXEC_INFO is invalid JSON", func(t *testing.T) {
		t.Setenv("KUBERNETES_EXEC_INFO", "invalid")
		_, err := reader.Read()
		if err == nil {
			t.Errorf("Read wants error but no error")
		}
	})
	t.Run("KUBERNETES_EXEC_INFO is v1", func(t *testing.T) {
		t.Setenv(
			"KUBERNETES_EXEC_INFO",
			`{"kind":"ExecCredential","apiVersion":"client.authentication.k8s.io/v1","spec":{"interactive":true}}`,
		)
		input, err := reader.Read()
		if err != nil {
			t.Errorf("Read returned error: %v", err)
		}
		want := credentialplugin.Input{ClientAuthenticationAPIVersion: "client.authentication.k8s.io/v1"}
		if diff := cmp.Diff(want, input); diff != "" {
			t.Errorf("input mismatch (-want +got):\n%s", diff)
		}
	})
}
