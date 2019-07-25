package tokencache

import (
	"encoding/json"
	"os"

	"github.com/google/wire"
	"github.com/int128/kubelogin/adaptors"
	"github.com/int128/kubelogin/models/credentialplugin"
	"golang.org/x/xerrors"
)

// Set provides an implementation and interface for Kubeconfig.
var Set = wire.NewSet(
	wire.Struct(new(Repository), "*"),
	wire.Bind(new(adaptors.TokenCacheRepository), new(*Repository)),
)

type Repository struct{}

func (*Repository) Read(filename string) (*credentialplugin.TokenCache, error) {
	f, err := os.Open(filename)
	if err != nil {
		return nil, xerrors.Errorf("could not open file %s: %w", filename, err)
	}
	defer f.Close()
	d := json.NewDecoder(f)
	var c credentialplugin.TokenCache
	if err := d.Decode(&c); err != nil {
		return nil, xerrors.Errorf("could not decode json file %s: %w", filename, err)
	}
	return &c, nil
}

func (*Repository) Write(filename string, tc credentialplugin.TokenCache) error {
	f, err := os.OpenFile(filename, os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return xerrors.Errorf("could not create file %s: %w", filename, err)
	}
	defer f.Close()
	e := json.NewEncoder(f)
	if err := e.Encode(&tc); err != nil {
		return xerrors.Errorf("could not encode json to file %s: %w", filename, err)
	}
	return nil
}
