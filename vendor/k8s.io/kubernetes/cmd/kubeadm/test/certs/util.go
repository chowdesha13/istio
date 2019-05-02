/*
Copyright 2017 The Kubernetes Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package certs

import (
	"crypto/rsa"
	"crypto/x509"
	"net"
	"path"
	"testing"

	certutil "k8s.io/client-go/util/cert"
	"k8s.io/kubernetes/cmd/kubeadm/app/util/pkiutil"
)

// SetupCertificateAuthorithy is a utility function for kubeadm testing that creates a
// CertificateAuthorithy cert/key pair
func SetupCertificateAuthorithy(t *testing.T) (*x509.Certificate, *rsa.PrivateKey) {
	caCert, caKey, err := pkiutil.NewCertificateAuthority(&certutil.Config{CommonName: "kubernetes"})
	if err != nil {
		t.Fatalf("failure while generating CA certificate and key: %v", err)
	}

	return caCert, caKey
}

// AssertCertificateIsCa is a utility function for kubeadm testing that asserts if a given certificate is a CA
func AssertCertificateIsCa(t *testing.T, cert *x509.Certificate) {
	if !cert.IsCA {
		t.Error("cert is not a valida CA")
	}
}

// AssertCertificateIsSignedByCa is a utility function for kubeadm testing that asserts if a given certificate is signed
// by the expected CA
func AssertCertificateIsSignedByCa(t *testing.T, cert *x509.Certificate, signingCa *x509.Certificate) {
	if err := cert.CheckSignatureFrom(signingCa); err != nil {
		t.Error("cert is not signed by signing CA as expected")
	}
}

// AssertCertificateHasCommonName is a utility function for kubeadm testing that asserts if a given certificate has
// the expected SubjectCommonName
func AssertCertificateHasCommonName(t *testing.T, cert *x509.Certificate, commonName string) {
	if cert.Subject.CommonName != commonName {
		t.Errorf("cert has Subject.CommonName %s, expected %s", cert.Subject.CommonName, commonName)
	}
}

// AssertCertificateHasOrganizations is a utility function for kubeadm testing that asserts if a given certificate has
// the expected Subject.Organization
func AssertCertificateHasOrganizations(t *testing.T, cert *x509.Certificate, organizations ...string) {
	for _, organization := range organizations {
		found := false
		for i := range cert.Subject.Organization {
			if cert.Subject.Organization[i] == organization {
				found = true
			}
		}
		if !found {
			t.Errorf("cert does not contain Subject.Organization %s as expected", organization)
		}
	}
}

// AssertCertificateHasClientAuthUsage is a utility function for kubeadm testing that asserts if a given certificate has
// the expected ExtKeyUsageClientAuth
func AssertCertificateHasClientAuthUsage(t *testing.T, cert *x509.Certificate) {
	for i := range cert.ExtKeyUsage {
		if cert.ExtKeyUsage[i] == x509.ExtKeyUsageClientAuth {
			return
		}
	}
	t.Error("cert has not ClientAuth usage as expected")
}

// AssertCertificateHasServerAuthUsage is a utility function for kubeadm testing that asserts if a given certificate has
// the expected ExtKeyUsageServerAuth
func AssertCertificateHasServerAuthUsage(t *testing.T, cert *x509.Certificate) {
	for i := range cert.ExtKeyUsage {
		if cert.ExtKeyUsage[i] == x509.ExtKeyUsageServerAuth {
			return
		}
	}
	t.Error("cert is not a ServerAuth")
}

// AssertCertificateHasDNSNames is a utility function for kubeadm testing that asserts if a given certificate has
// the expected DNSNames
func AssertCertificateHasDNSNames(t *testing.T, cert *x509.Certificate, DNSNames ...string) {
	for _, DNSName := range DNSNames {
		found := false
		for _, val := range cert.DNSNames {
			if val == DNSName {
				found = true
				break
			}
		}

		if !found {
			t.Errorf("cert does not contain DNSName %s", DNSName)
		}
	}
}

// AssertCertificateHasIPAddresses is a utility function for kubeadm testing that asserts if a given certificate has
// the expected IPAddresses
func AssertCertificateHasIPAddresses(t *testing.T, cert *x509.Certificate, IPAddresses ...net.IP) {
	for _, IPAddress := range IPAddresses {
		found := false
		for _, val := range cert.IPAddresses {
			if val.Equal(IPAddress) {
				found = true
				break
			}
		}

		if !found {
			t.Errorf("cert does not contain IPAddress %s", IPAddress)
		}
	}
}

// CreateCACert creates a generic CA cert.
func CreateCACert(t *testing.T) (*x509.Certificate, *rsa.PrivateKey) {
	certCfg := &certutil.Config{CommonName: "kubernetes"}
	cert, key, err := pkiutil.NewCertificateAuthority(certCfg)
	if err != nil {
		t.Fatalf("couldn't create CA: %v", err)
	}
	return cert, key
}

// CreateTestCert makes a generic certficate with the given CA.
func CreateTestCert(t *testing.T, caCert *x509.Certificate, caKey *rsa.PrivateKey) (*x509.Certificate, *rsa.PrivateKey) {
	cert, key, err := pkiutil.NewCertAndKey(caCert, caKey,
		&certutil.Config{
			CommonName: "testCert",
			Usages:     []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
		})
	if err != nil {
		t.Fatalf("couldn't create test cert: %v", err)
	}
	return cert, key
}

// CertTestCase is a configuration of certificates and whether it's expected to work.
type CertTestCase struct {
	Name        string
	Files       PKIFiles
	ExpectError bool
}

// GetSparseCertTestCases produces a series of cert configurations and their intended outcomes.
func GetSparseCertTestCases(t *testing.T) []CertTestCase {

	caCert, caKey := CreateCACert(t)
	fpCACert, fpCAKey := CreateCACert(t)
	etcdCACert, etcdCAKey := CreateCACert(t)

	fpCert, fpKey := CreateTestCert(t, fpCACert, fpCAKey)

	return []CertTestCase{
		{
			Name: "nothing present",
		},
		{
			Name: "CAs already exist",
			Files: PKIFiles{
				"ca.crt":             caCert,
				"ca.key":             caKey,
				"front-proxy-ca.crt": fpCACert,
				"front-proxy-ca.key": fpCAKey,
				"etcd/ca.crt":        etcdCACert,
				"etcd/ca.key":        etcdCAKey,
			},
		},
		{
			Name: "CA certs only",
			Files: PKIFiles{
				"ca.crt":             caCert,
				"front-proxy-ca.crt": fpCACert,
				"etcd/ca.crt":        etcdCACert,
			},
			ExpectError: true,
		},
		{
			Name: "FrontProxyCA with certs",
			Files: PKIFiles{
				"ca.crt":                 caCert,
				"ca.key":                 caKey,
				"front-proxy-ca.crt":     fpCACert,
				"front-proxy-client.crt": fpCert,
				"front-proxy-client.key": fpKey,
				"etcd/ca.crt":            etcdCACert,
				"etcd/ca.key":            etcdCAKey,
			},
		},
		{
			Name: "FrontProxy certs missing CA",
			Files: PKIFiles{
				"front-proxy-client.crt": fpCert,
				"front-proxy-client.key": fpKey,
			},
			ExpectError: true,
		},
	}
}

// PKIFiles are a list of files that should be created for a test case
type PKIFiles map[string]interface{}

// WritePKIFiles writes the given files out to the given directory
func WritePKIFiles(t *testing.T, dir string, files PKIFiles) {
	for filename, body := range files {
		switch body := body.(type) {
		case *x509.Certificate:
			if err := certutil.WriteCert(path.Join(dir, filename), certutil.EncodeCertPEM(body)); err != nil {
				t.Errorf("unable to write certificate to file %q: [%v]", dir, err)
			}
		case *rsa.PublicKey:
			publicKeyBytes, err := certutil.EncodePublicKeyPEM(body)
			if err != nil {
				t.Errorf("unable to write public key to file %q: [%v]", filename, err)
			}
			if err := certutil.WriteKey(path.Join(dir, filename), publicKeyBytes); err != nil {
				t.Errorf("unable to write public key to file %q: [%v]", filename, err)
			}
		case *rsa.PrivateKey:
			if err := certutil.WriteKey(path.Join(dir, filename), certutil.EncodePrivateKeyPEM(body)); err != nil {
				t.Errorf("unable to write private key to file %q: [%v]", filename, err)
			}
		}
	}
}
