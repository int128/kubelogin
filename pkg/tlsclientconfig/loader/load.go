// Package loader provides loading certificates from files or base64 encoded string.
package loader

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"os"

	"github.com/google/wire"
	"github.com/int128/kubelogin/pkg/tlsclientconfig"
)

// Set provides an implementation and interface.
var Set = wire.NewSet(
	wire.Struct(new(Loader), "*"),
	wire.Bind(new(Interface), new(*Loader)),
)

type Interface interface {
	Load(config tlsclientconfig.Config) (*tls.Config, error)
}

// Loader represents a pool of certificates.
type Loader struct{}

func (l *Loader) Load(config tlsclientconfig.Config) (*tls.Config, error) {
	rootCAs := x509.NewCertPool()
	for _, f := range config.CACertFilename {
		if err := addFile(rootCAs, f); err != nil {
			return nil, fmt.Errorf("could not load the certificate from %s: %w", f, err)
		}
	}
	for _, d := range config.CACertData {
		if err := addBase64Encoded(rootCAs, d); err != nil {
			return nil, fmt.Errorf("could not load the certificate: %w", err)
		}
	}
	if rootCAs.Equal(x509.NewCertPool()) {
		// if empty, use the host's root CA set
		rootCAs = nil
	}
	return &tls.Config{
		RootCAs:            rootCAs,
		InsecureSkipVerify: config.SkipTLSVerify,
		Renegotiation:      config.Renegotiation,
	}, nil
}

func addFile(p *x509.CertPool, filename string) error {
	b, err := os.ReadFile(filename)
	if err != nil {
		return fmt.Errorf("could not read: %w", err)
	}
	if !p.AppendCertsFromPEM(b) {
		return errors.New("invalid certificate")
	}
	return nil
}

func addBase64Encoded(p *x509.CertPool, s string) error {
	b, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return fmt.Errorf("could not decode base64: %w", err)
	}
	if !p.AppendCertsFromPEM(b) {
		return errors.New("invalid certificate")
	}
	return nil
}
