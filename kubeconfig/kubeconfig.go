package kubeconfig

import (
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/client-go/tools/clientcmd/api"
)

// Read parses the file and returns the Config.
func Read(path string) (*api.Config, error) {
	return clientcmd.LoadFromFile(path)
}

// Write writes the config to the file.
func Write(config *api.Config, path string) error {
	return clientcmd.WriteToFile(*config, path)
}
