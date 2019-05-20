package adaptors

import (
	"github.com/int128/kubelogin/kubeconfig"
	"github.com/pkg/errors"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/client-go/tools/clientcmd/api"
)

type KubeConfig struct{}

// LoadByDefaultRules loads the config by the default rules, that is same as kubectl.
func (*KubeConfig) LoadByDefaultRules(filename string) (*kubeconfig.Config, error) {
	rules := clientcmd.NewDefaultClientConfigLoadingRules()
	rules.ExplicitPath = filename
	config, err := rules.Load()
	if err != nil {
		return nil, errors.Wrapf(err, "could not read the kubeconfig")
	}
	return (*kubeconfig.Config)(config), err
}

// LoadFromFile loads the config from the single file.
func (*KubeConfig) LoadFromFile(filename string) (*kubeconfig.Config, error) {
	config, err := clientcmd.LoadFromFile(filename)
	if err != nil {
		return nil, errors.Wrapf(err, "could not read the kubeconfig from %s", filename)
	}
	return (*kubeconfig.Config)(config), err
}

// WriteToFile writes the config to the single file.
func (*KubeConfig) WriteToFile(config *kubeconfig.Config, filename string) error {
	err := clientcmd.WriteToFile(*(*api.Config)(config), filename)
	if err != nil {
		return errors.Wrapf(err, "could not write the kubeconfig to %s", filename)
	}
	return err
}
