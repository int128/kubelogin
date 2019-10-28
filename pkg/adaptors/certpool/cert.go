package certpool

import (
	"crypto/x509"
	"encoding/base64"
	"io/ioutil"

	"github.com/google/wire"
	"golang.org/x/xerrors"
)

//go:generate mockgen -destination mock_certpool/mock_certpool.go github.com/int128/kubelogin/pkg/adaptors/certpool FactoryInterface,Interface

// Set provides an implementation and interface for Kubeconfig.
var Set = wire.NewSet(
	wire.Struct(new(Factory), "*"),
	wire.Bind(new(FactoryInterface), new(*Factory)),
	wire.Struct(new(CertPool), "*"),
	wire.Bind(new(Interface), new(*CertPool)),
)

type FactoryInterface interface {
	New() Interface
}

type Factory struct{}

func (f *Factory) New() Interface {
	return &CertPool{pool: x509.NewCertPool()}
}

type Interface interface {
	LoadFromFile(filename string) error
	LoadBase64(s string) error
	GetX509CertPool() *x509.CertPool // returns the CertPool if it has one or more certificates, otherwise nil
}

type CertPool struct {
	pool *x509.CertPool
}

func (p *CertPool) GetX509CertPool() *x509.CertPool {
	if len(p.pool.Subjects()) > 0 {
		return p.pool
	}
	return nil
}

func (p *CertPool) LoadFromFile(filename string) error {
	b, err := ioutil.ReadFile(filename)
	if err != nil {
		return xerrors.Errorf("could not read %s: %w", filename, err)
	}
	if !p.pool.AppendCertsFromPEM(b) {
		return xerrors.Errorf("could not append certificate from %s", filename)
	}
	return nil
}

func (p *CertPool) LoadBase64(s string) error {
	b, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return xerrors.Errorf("could not decode base64: %w", err)
	}
	if !p.pool.AppendCertsFromPEM(b) {
		return xerrors.Errorf("could not append certificate")
	}
	return nil
}
