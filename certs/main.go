package main

import (
	"fmt"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/seemenkina/tss-lib-test/tssInterface"
)

func main() {

	KeyLib := make(tssInterface.Library)
	rootIdBig := tssInterface.GenerateRandId()
	rootId := tssInterface.CalculateIdHash(rootIdBig)
	tssInterface.CreateUserDir(rootId)

	agentIdBig := tssInterface.GenerateRandId()
	agentId := tssInterface.CalculateIdHash(agentIdBig)
	tssInterface.CreateUserDir(agentId)

	pks := tssInterface.GenerateKey(1, 2, rootId)

	_, callerFileName, _, _ := runtime.Caller(0)
	srcDirName := filepath.Dir(callerFileName)
	certDirName := fmt.Sprintf("%s/data/agent_%s/cert", srcDirName, rootId)

	if ok, err := tssInterface.IsEmptyDir(certDirName); err == nil && ok == true {
		rootCert, rootCertPEM, err := tssInterface.GenRootCA(pks, rootIdBig)
		if err != nil {
			fmt.Printf("%s\n", err)
		}

		KeyLib[rootId] = &pks

		pks2 := tssInterface.GenerateKey(1, 2, agentId)

		interCert, certPEM, err := tssInterface.GenerateCA(rootCert, pks2, pks, agentIdBig)
		if err != nil {
			fmt.Printf("%s\n", err)
		}

		KeyLib[tssInterface.CalculateIdHash(interCert.SerialNumber)] = &pks2

		tssInterface.SaveCertificates(rootCertPEM, strings.ReplaceAll(rootCert.Subject.CommonName, " ", "_"), rootId)
		tssInterface.SaveCertificates(certPEM, strings.ReplaceAll(interCert.Subject.CommonName, " ", "_"), agentId)

		tssInterface.Verify(rootCert, interCert)

		err = KeyLib.WriteLibrary()
		if err != nil {
			fmt.Printf("%s\n", err)
		}

	} else {
		err := KeyLib.LoadLibrary()
		if err != nil {
			fmt.Printf("%s\n", err)
		}

		rootCert, _ := tssInterface.LoadLeafCertificate(fmt.Sprintf("data/agent_%s/cert/certificate_Root.pem", rootId))
		interCert, _ := tssInterface.LoadLeafCertificate(fmt.Sprintf("data/agent_%s/cert/certificate_Leaf.pem", agentId))

		tssInterface.Verify(rootCert, interCert)
	}

}
