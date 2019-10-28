// Package certpool provides loading certificates from files or base64 encoded string.
package certpool

import (
	"crypto/x509"
	"encoding/base64"
	"io/ioutil"

	"github.com/google/wire"
	"golang.org/x/xerrors"
)

//go:generate mockgen -destination mock_certpool/mock_certpool.go github.com/int128/kubelogin/pkg/adaptors/certpool FactoryInterface,Interface

// Set provides an implementation and interface.
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

// New returns an instance which implements the Interface.
func (f *Factory) New() Interface {
	return &CertPool{pool: x509.NewCertPool()}
}

type Interface interface {
	AddFile(filename string) error
	AddBase64Encoded(s string) error
	GetX509OrNil() *x509.CertPool // returns nil if it has no certificate
}

// CertPool represents a pool of certificates.
type CertPool struct {
	pool *x509.CertPool
}

// GetX509OrNil returns x509.CertPool.
// It returns nil if it has no certificate.
func (p *CertPool) GetX509OrNil() *x509.CertPool {
	if len(p.pool.Subjects()) > 0 {
		return p.pool
	}
	return nil
}

// AddFile loads the certificate from the file.
func (p *CertPool) AddFile(filename string) error {
	b, err := ioutil.ReadFile(filename)
	if err != nil {
		return xerrors.Errorf("could not read %s: %w", filename, err)
	}
	if !p.pool.AppendCertsFromPEM(b) {
		return xerrors.Errorf("could not append certificate from %s", filename)
	}
	return nil
}

// AddBase64Encoded loads the certificate from the base64 encoded string.
func (p *CertPool) AddBase64Encoded(s string) error {
	b, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return xerrors.Errorf("could not decode base64: %w", err)
	}
	if !p.pool.AppendCertsFromPEM(b) {
		return xerrors.Errorf("could not append certificate")
	}
	return nil
}
