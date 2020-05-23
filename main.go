package main

import (
	"fmt"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/seemenkina/tss-lib-test/cert"
	"github.com/seemenkina/tss-lib-test/utils"
)

func main() {

	pks := cert.GenerateKey(utils.TestThreshold, utils.TestParticipants)

	_, callerFileName, _, _ := runtime.Caller(0)
	srcDirName := filepath.Dir(callerFileName)
	certDirName := fmt.Sprintf("%s/test_data/cert", srcDirName)

	if ok, err := utils.IsEmptyDir(certDirName); err == nil && ok == true {
		rootCert, rootCertPEM, err := cert.GenRootCA(pks)
		if err != nil {
			fmt.Printf("%s\n", err)
		}

		interCert, certPEM, err := cert.GenerateCA(rootCert, pks)
		if err != nil {
			fmt.Printf("%s\n", err)
		}

		utils.SaveCertificates(rootCertPEM, strings.ReplaceAll(rootCert.Subject.CommonName, " ", "_"))
		utils.SaveCertificates(certPEM, strings.ReplaceAll(interCert.Subject.CommonName, " ", "_"))

		cert.Verify(rootCert, interCert)
		// cert.VerifyPEM(rootCertPEM, certPEM)
	} else {
		// rootCert,_ := utils.LoadCertificate("Root_CA")
		// interCert,_ := utils.LoadCertificate("Intermediate_CA")

		// cert.Verify(rootCert, interCert)
	}

}
