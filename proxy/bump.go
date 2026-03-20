package proxy

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"math/big"
	"net"
	"sync"
	"time"
)

// CertAuthority holds the CA certificate and key used to sign leaf certs
// for SSL bump (MITM) connections.
type CertAuthority struct {
	Cert    *x509.Certificate
	Key     *ecdsa.PrivateKey
	TLSCert tls.Certificate // CA cert + key for tls.Config

	mu    sync.RWMutex
	cache map[string]*tls.Certificate // hostname → leaf cert
}

// NewCertAuthority generates a new self-signed CA for SSL bump.
func NewCertAuthority() (*CertAuthority, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("ca: generate key: %w", err)
	}

	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, fmt.Errorf("ca: generate serial: %w", err)
	}

	template := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			Organization: []string{"Capsule Access Plane"},
			CommonName:   "Capsule MITM CA",
		},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            0,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		return nil, fmt.Errorf("ca: create certificate: %w", err)
	}

	caCert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return nil, fmt.Errorf("ca: parse certificate: %w", err)
	}

	tlsCert := tls.Certificate{
		Certificate: [][]byte{certDER},
		PrivateKey:  key,
		Leaf:        caCert,
	}

	return &CertAuthority{
		Cert:    caCert,
		Key:     key,
		TLSCert: tlsCert,
		cache:   make(map[string]*tls.Certificate),
	}, nil
}

// GetCertificate returns a TLS certificate for the given hostname,
// generating and caching it on first request.
func (ca *CertAuthority) GetCertificate(hostname string) (*tls.Certificate, error) {
	ca.mu.RLock()
	if cert, ok := ca.cache[hostname]; ok {
		ca.mu.RUnlock()
		return cert, nil
	}
	ca.mu.RUnlock()

	ca.mu.Lock()
	defer ca.mu.Unlock()

	// Double-check after acquiring write lock.
	if cert, ok := ca.cache[hostname]; ok {
		return cert, nil
	}

	cert, err := ca.generateLeaf(hostname)
	if err != nil {
		return nil, err
	}
	ca.cache[hostname] = cert
	return cert, nil
}

// TLSConfigForClient returns a tls.Config that serves dynamically generated
// certs for any hostname. Suitable for use as a MITM TLS server.
func (ca *CertAuthority) TLSConfigForClient() *tls.Config {
	return &tls.Config{
		GetCertificate: func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
			return ca.GetCertificate(hello.ServerName)
		},
	}
}

// CACertPool returns a cert pool containing the CA certificate,
// suitable for use as a client's RootCAs to trust MITM'd connections.
func (ca *CertAuthority) CACertPool() *x509.CertPool {
	pool := x509.NewCertPool()
	pool.AddCert(ca.Cert)
	return pool
}

func (ca *CertAuthority) generateLeaf(hostname string) (*tls.Certificate, error) {
	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("leaf: generate key: %w", err)
	}

	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, fmt.Errorf("leaf: generate serial: %w", err)
	}

	template := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName: hostname,
		},
		NotBefore: time.Now().Add(-time.Minute),
		NotAfter:  time.Now().Add(24 * time.Hour),
		KeyUsage:  x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{
			x509.ExtKeyUsageServerAuth,
		},
	}

	// Support both hostnames and IP addresses.
	if ip := net.ParseIP(hostname); ip != nil {
		template.IPAddresses = []net.IP{ip}
	} else {
		template.DNSNames = []string{hostname}
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, ca.Cert, &leafKey.PublicKey, ca.Key)
	if err != nil {
		return nil, fmt.Errorf("leaf: create certificate: %w", err)
	}

	return &tls.Certificate{
		Certificate: [][]byte{certDER},
		PrivateKey:  leafKey,
	}, nil
}
