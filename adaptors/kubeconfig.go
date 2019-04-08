package adaptors

import (
	"github.com/pkg/errors"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/client-go/tools/clientcmd/api"
)

type KubeConfig struct{}

func (*KubeConfig) LoadFromFile(filename string) (*api.Config, error) {
	config, err := clientcmd.LoadFromFile(filename)
	if err != nil {
		return nil, errors.Wrapf(err, "could not read the kubeconfig from %s", filename)
	}
	return config, err
}

func (*KubeConfig) WriteToFile(config *api.Config, filename string) error {
	err := clientcmd.WriteToFile(*config, filename)
	if err != nil {
		return errors.Wrapf(err, "could not write the kubeconfig to %s", filename)
	}
	return err
}
