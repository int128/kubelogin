package kubeconfig

import (
	"fmt"
	"os"

	homedir "github.com/mitchellh/go-homedir"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/client-go/tools/clientcmd/api"
)

const userKubeConfig = "~/.kube/config"

// Find returns path to the kubeconfig file,
// that is given by env:KUBECONFIG or default ~/.kube/config.
func Find() (string, error) {
	env := os.Getenv("KUBECONFIG")
	if env != "" {
		return env, nil
	}
	path, err := homedir.Expand(userKubeConfig)
	if err != nil {
		return "", fmt.Errorf("Could not expand %s: %s", userKubeConfig, err)
	}
	return path, nil
}

func Load(path string) (*api.Config, error) {
	config, err := clientcmd.LoadFromFile(path)
	if err != nil {
		return nil, fmt.Errorf("Could not load kubeconfig from %s: %s", path, err)
	}
	return config, nil
}

func Write(config *api.Config, path string) error {
	return clientcmd.WriteToFile(*config, path)
}
