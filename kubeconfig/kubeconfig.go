package kubeconfig

import (
	"fmt"

	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/client-go/tools/clientcmd/api"
)

// Read parses the file and returns the Config.
func Read(path string) (*api.Config, error) {
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
