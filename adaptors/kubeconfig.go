package adaptors

import (
	"github.com/int128/kubelogin/adaptors/interfaces"
	"github.com/int128/kubelogin/kubeconfig"
	"github.com/pkg/errors"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/client-go/tools/clientcmd/api"
)

func NewKubeConfig() adaptors.KubeConfig {
	return &KubeConfig{}
}

type KubeConfig struct{}

func (*KubeConfig) LoadFromFile(filename string) (*kubeconfig.KubeConfig, error) {
	config, err := clientcmd.LoadFromFile(filename)
	if err != nil {
		return nil, errors.Wrapf(err, "could not read the kubeconfig from %s", filename)
	}
	return (*kubeconfig.KubeConfig)(config), err
}

func (*KubeConfig) WriteToFile(config *kubeconfig.KubeConfig, filename string) error {
	err := clientcmd.WriteToFile(*(*api.Config)(config), filename)
	if err != nil {
		return errors.Wrapf(err, "could not write the kubeconfig to %s", filename)
	}
	return err
}
