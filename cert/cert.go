package cert

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"time"

	"github.com/seemenkina/tss-lib-test/keygen"
	"github.com/seemenkina/tss-lib-test/sign"
	"golang.org/x/crypto/cryptobyte"
	"golang.org/x/crypto/cryptobyte/asn1"
)

type PrivateKeyCert struct {
	pk ecdsa.PublicKey
}

func GenerateKey() PrivateKeyCert {
	key := keygen.GenerateKeys()
	pks := PrivateKeyCert{}
	ecdsaPk := ecdsa.PublicKey{
		Curve: elliptic.P256(),
		X:     key.ECDSAPub.X(),
		Y:     key.ECDSAPub.Y(),
	}
	pks.pk = ecdsaPk
	return pks
}

func (p *PrivateKeyCert) Public() crypto.PublicKey {
	return &p.pk
}

func (p *PrivateKeyCert) Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) (signature []byte, err error) {
	msg := &big.Int{}
	msg.SetBytes(digest)

	signatureData := sign.NewSigning(msg)
	R := &big.Int{}
	R.SetBytes(signatureData.GetR())
	S := &big.Int{}
	S.SetBytes(signatureData.GetS())

	var b cryptobyte.Builder
	b.AddASN1(asn1.SEQUENCE, func(b *cryptobyte.Builder) {
		b.AddASN1BigInt(R)
		b.AddASN1BigInt(S)
	})

	return b.Bytes()
}

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

func GenRootCA(key PrivateKeyCert) (*x509.Certificate, []byte, error) {
	var rootTemp = x509.Certificate{
		SerialNumber: big.NewInt(2020),
		Subject: pkix.Name{
			Country:      []string{"SE"},
			Organization: []string{"Company Co."},
			CommonName:   "Root CA",
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(10, 0, 0),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            1,
	}

	return generateCA(&rootTemp, &rootTemp, &key.pk, &key)
}

func GenerateCA(RootCA *x509.Certificate, keyRoot PrivateKeyCert) (*x509.Certificate, []byte, error) {
	var caTemp = x509.Certificate{
		SerialNumber: big.NewInt(2021),
		Subject: pkix.Name{
			Country:      []string{"SE"},
			Organization: []string{"Company Co."},
			CommonName:   "Intermediate CA",
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(10, 0, 0),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            2,
	}

	ecdsaKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("Failed to generate key: %s\n", err)
	}

	return generateCA(&caTemp, RootCA, &ecdsaKey.PublicKey, &keyRoot)
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

func VerifyPEM(rootCert, interCert []byte) {
	roots := x509.NewCertPool()
	roots.AppendCertsFromPEM(rootCert)

	block, _ := pem.Decode([]byte(interCert))
	if block == nil {
		fmt.Println("failed to parse certificate PEM")
		return
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		fmt.Println("failed to parse certificate: " + err.Error())
		return
	}

	opts := x509.VerifyOptions{
		Roots:         roots,
		Intermediates: x509.NewCertPool(),
	}

	if _, err := cert.Verify(opts); err != nil {
		fmt.Println("failed to verify certificate: " + err.Error())
		return
	}

	fmt.Println("verification succeeds")
}
