package main

import (
	"crypto/x509"
	"fmt"
	"io/ioutil"

	"github.com/tss-lib-test/cert"
)

func main() {

	pks := cert.PrivateKeyCert{}

	pks.GenerateKey()

	RootCert, RootCertPEM, err := cert.GenRootCA(pks)
	if err != nil {
		fmt.Printf("%s\n", err)
	}

	_ = ioutil.WriteFile("test_data/cert/rootCert.pem", RootCertPEM, 0777)
	fmt.Println("certificate saved to rootCert.pem")

	Cert, CertPEM, err := cert.GenerateCA(RootCert, pks)
	if err != nil {
		fmt.Printf("%s\n", err)
	}

	_ = ioutil.WriteFile("test_data/cert/cert.pem", CertPEM, 0777)
	fmt.Println("certificate saved to cert_util.pem")

	roots := x509.NewCertPool()
	roots.AddCert(RootCert)

	opts := x509.VerifyOptions{
		Roots: roots,
	}

	if _, err := Cert.Verify(opts); err != nil {
		fmt.Println("failed to verify certificate: " + err.Error())
	}
	fmt.Println("Success Verify certificate")
}
