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
// that is given by env:KUBECONFIG or ~/.kube/config.
// This returns an error if it is not found or I/O error occurred.
func Find() (string, error) {
	path := os.Getenv("KUBECONFIG")
	if path == "" {
		var err error
		path, err = homedir.Expand(userKubeConfig)
		if err != nil {
			return "", fmt.Errorf("Could not expand %s: %s", userKubeConfig, err)
		}
	}
	info, err := os.Stat(path)
	if err != nil {
		return "", fmt.Errorf("Could not stat %s: %s", userKubeConfig, err)
	}
	if info.IsDir() {
		return "", fmt.Errorf("%s should be a file", userKubeConfig)
	}
	return path, nil
}

// Load loads the file and returns the Config.
func Load(path string) (*api.Config, error) {
	config, err := clientcmd.LoadFromFile(path)
	if err != nil {
		return nil, fmt.Errorf("Could not load kubeconfig from %s: %s", path, err)
	}
	return config, nil
}

// Write writes the config to the file.
func Write(config *api.Config, path string) error {
	return clientcmd.WriteToFile(*config, path)
}
