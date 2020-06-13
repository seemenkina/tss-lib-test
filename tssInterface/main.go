package tssInterface

import (
	"fmt"
	"path/filepath"
	"runtime"
	"strings"
)

func main() {

	KeyLib := make(Library)
	rootIdBig := GenerateRandId()
	rootId := CalculateIdHash(rootIdBig)
	CreateUserDir(rootId)

	agentIdBig := GenerateRandId()
	agentId := CalculateIdHash(agentIdBig)
	CreateUserDir(agentId)

	pks := GenerateKey(1, 2, rootId)

	_, callerFileName, _, _ := runtime.Caller(0)
	srcDirName := filepath.Dir(callerFileName)
	certDirName := fmt.Sprintf("%s/data/agent_%s/cert", srcDirName, rootId)

	if ok, err := IsEmptyDir(certDirName); err == nil && ok == true {
		rootCert, rootCertPEM, err := GenRootCA(pks, rootIdBig)
		if err != nil {
			fmt.Printf("%s\n", err)
		}

		KeyLib[rootId] = &pks

		pks2 := GenerateKey(1, 2, agentId)

		interCert, certPEM, err := GenerateCA(rootCert, pks2, pks, agentIdBig)
		if err != nil {
			fmt.Printf("%s\n", err)
		}

		KeyLib[CalculateIdHash(interCert.SerialNumber)] = &pks2

		SaveCertificates(rootCertPEM, strings.ReplaceAll(rootCert.Subject.CommonName, " ", "_"), rootId)
		SaveCertificates(certPEM, strings.ReplaceAll(interCert.Subject.CommonName, " ", "_"), agentId)

		Verify(rootCert, interCert)

		err = KeyLib.WriteLibrary()
		if err != nil {
			fmt.Printf("%s\n", err)
		}

	} else {
		err := KeyLib.LoadLibrary()
		if err != nil {
			fmt.Printf("%s\n", err)
		}

		rootCert, _ := LoadLeafCertificate(fmt.Sprintf("data/agent_%s/cert/certificate_Root.pem", rootId))
		interCert, _ := LoadLeafCertificate(fmt.Sprintf("data/agent_%s/cert/certificate_Leaf.pem", agentId))

		Verify(rootCert, interCert)
	}

}
