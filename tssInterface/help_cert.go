package tssInterface

import (
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"time"
)

func generateCA(temp, parent *x509.Certificate, pubKey interface{}, rootPrivateKey interface{}) (*x509.Certificate, []byte, error) {
	certBytes, err := x509.CreateCertificate(rand.Reader, temp, parent, pubKey, rootPrivateKey)
	if err != nil {
		return nil, nil, fmt.Errorf("Failed to create certificate: %s\n", err)
	}

	cert, err := x509.ParseCertificate(certBytes)
	if err != nil {
		return nil, nil, fmt.Errorf("Failed to parse certificate: %s\n", err)
	}

	b := pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certBytes,
	}
	certPEM := pem.EncodeToMemory(&b)

	return cert, certPEM, nil
}

func GenRootCA(key PrivateKeyCert, id *big.Int) (*x509.Certificate, []byte, error) {
	var rootTemp = x509.Certificate{
		SerialNumber: id,
		Subject: pkix.Name{
			Country:      []string{"US"},
			Organization: []string{"SPIFFE"},
			CommonName:   "Root",
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(5, 0, 0),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            1,
	}

	return generateCA(&rootTemp, &rootTemp, &key.Pk, &key)
}

func GenerateCA(RootCA *x509.Certificate, key, keyRoot PrivateKeyCert, id *big.Int) (*x509.Certificate, []byte, error) {
	var caTemp = x509.Certificate{
		SerialNumber: id,
		Subject: pkix.Name{
			Country:      []string{"US"},
			Organization: []string{"SPIFFE"},
			CommonName:   "Leaf",
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(5, 0, 0),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyAgreement | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
		IsCA:                  false,
		MaxPathLen:            2,
	}

	// ecdsaKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	// if err != nil {
	// 	return nil, nil, fmt.Errorf("Failed to generate key: %s\n", err)
	// }

	p, r, e := generateCA(&caTemp, RootCA, &key.Pk, &keyRoot)

	return p, r, e
}

func Verify(rootCert, interCert *x509.Certificate) {
	roots := x509.NewCertPool()
	roots.AddCert(rootCert)

	opts := x509.VerifyOptions{
		Roots: roots,
	}

	if _, err := interCert.Verify(opts); err != nil {
		fmt.Println("failed to verify certificate: " + err.Error())
		return
	}
	fmt.Println("Success Verify certificate")
}
