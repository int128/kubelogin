package kubeconfig

import (
	"os"
	"testing"
)

func TestKubeConfig_LoadByDefaultRules(t *testing.T) {
	var adaptor KubeConfig

	t.Run("google.yaml>keycloak.yaml", func(t *testing.T) {
		setenv(t, "KUBECONFIG", "testdata/kubeconfig.google.yaml"+string(os.PathListSeparator)+"testdata/kubeconfig.keycloak.yaml")
		defer unsetenv(t, "KUBECONFIG")

		config, err := adaptor.LoadByDefaultRules("")
		if err != nil {
			t.Fatalf("Could not load the configs: %s", err)
		}
		if w := "google@hello.k8s.local"; w != config.CurrentContext {
			t.Errorf("CurrentContext wants %s but %s", w, config.CurrentContext)
		}
		if _, ok := config.Contexts["google@hello.k8s.local"]; !ok {
			t.Errorf("Contexts[google@hello.k8s.local] is missing")
		}
		if _, ok := config.Contexts["keycloak@hello.k8s.local"]; !ok {
			t.Errorf("Contexts[keycloak@hello.k8s.local] is missing")
		}
		if _, ok := config.AuthInfos["google"]; !ok {
			t.Errorf("AuthInfos[google] is missing")
		}
		if _, ok := config.AuthInfos["keycloak"]; !ok {
			t.Errorf("AuthInfos[keycloak] is missing")
		}
	})

	t.Run("keycloak.yaml>google.yaml", func(t *testing.T) {
		setenv(t, "KUBECONFIG", "testdata/kubeconfig.keycloak.yaml"+string(os.PathListSeparator)+"testdata/kubeconfig.google.yaml")
		defer unsetenv(t, "KUBECONFIG")

		config, err := adaptor.LoadByDefaultRules("")
		if err != nil {
			t.Fatalf("Could not load the configs: %s", err)
		}
		if w := "keycloak@hello.k8s.local"; w != config.CurrentContext {
			t.Errorf("CurrentContext wants %s but %s", w, config.CurrentContext)
		}
		if _, ok := config.Contexts["google@hello.k8s.local"]; !ok {
			t.Errorf("Contexts[google@hello.k8s.local] is missing")
		}
		if _, ok := config.Contexts["keycloak@hello.k8s.local"]; !ok {
			t.Errorf("Contexts[keycloak@hello.k8s.local] is missing")
		}
		if _, ok := config.AuthInfos["google"]; !ok {
			t.Errorf("AuthInfos[google] is missing")
		}
		if _, ok := config.AuthInfos["keycloak"]; !ok {
			t.Errorf("AuthInfos[keycloak] is missing")
		}
	})
}

func setenv(t *testing.T, key, value string) {
	t.Helper()
	if err := os.Setenv(key, value); err != nil {
		t.Fatalf("Could not set the env var %s=%s: %s", key, value, err)
	}
}

func unsetenv(t *testing.T, key string) {
	t.Helper()
	if err := os.Unsetenv(key); err != nil {
		t.Fatalf("Could not unset the env var %s: %s", key, err)
	}
}
