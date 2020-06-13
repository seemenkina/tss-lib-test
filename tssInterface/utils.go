package tssInterface

import (
	"crypto/sha1"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"math/big"
	"math/rand"
	"os"
	"path/filepath"
	"runtime"
	"sort"

	"github.com/binance-chain/tss-lib/common"
	"github.com/binance-chain/tss-lib/ecdsa/keygen"
	"github.com/binance-chain/tss-lib/tss"
	"github.com/ipfs/go-log"
	"github.com/pkg/errors"
)

// const (
// 	TestParticipants = 2
// 	TestThreshold    = 1
// )

const (
	testFixtureDirFormat  = "%s/../data/agent_%s/ecdsa_data"
	testCertDirFormat     = "%s/../data/agent_%s/cert"
	testFixtureFileFormat = "keygen_data_%d.json"
	testCertFileFormat    = "certificate_%s.pem"
)

func SetUp(level string) {
	if err := log.SetLogLevel("tss-lib", level); err != nil {
		panic(err)
	}
}

func CreateUserDir(id string) {
	_, callerFileName, _, _ := runtime.Caller(0)
	srcDirName := filepath.Dir(callerFileName)
	userDirName := fmt.Sprintf("%s/../data/agent_%s/ecdsa_data", srcDirName, id)
	if _, err := os.Stat(userDirName); os.IsNotExist(err) {
		_ = os.MkdirAll(userDirName, 0700)
	}
	userDirName2 := fmt.Sprintf("%s/../data/agent_%s/cert", srcDirName, id)
	if _, err := os.Stat(userDirName2); os.IsNotExist(err) {
		_ = os.MkdirAll(userDirName2, 0700)
	}
}

func makeTestFixtureFilePath(partyIndex int, id string) string {
	_, callerFileName, _, _ := runtime.Caller(0)
	srcDirName := filepath.Dir(callerFileName)
	fixtureDirName := fmt.Sprintf(testFixtureDirFormat, srcDirName, id)
	return fmt.Sprintf("%s/"+testFixtureFileFormat, fixtureDirName, partyIndex)
}

func makeTestCertFilePath(name string, id string) string {
	_, callerFileName, _, _ := runtime.Caller(0)
	srcDirName := filepath.Dir(callerFileName)
	certDirName := fmt.Sprintf(testCertDirFormat, srcDirName, id)
	return fmt.Sprintf("%s/"+testCertFileFormat, certDirName, name)
}

func TryWriteTestFixtureFile(index int, data keygen.LocalPartySaveData, id string) {
	fixtureFileName := makeTestFixtureFilePath(index, id)

	// fixture file does not already exist?
	// if it does, we won't re-create it here
	fi, err := os.Stat(fixtureFileName)
	if !(err == nil && fi != nil && !fi.IsDir()) {
		fd, err := os.OpenFile(fixtureFileName, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
		if err != nil {
			common.Logger.Errorf("unable to open fixture file %s for writing", fixtureFileName)
		}
		bz, err := json.Marshal(&data)
		if err != nil {
			common.Logger.Fatalf("unable to marshal save data for fixture file %s", fixtureFileName)
		}
		_, err = fd.Write(bz)
		if err != nil {
			common.Logger.Fatalf("unable to write to fixture file %s", fixtureFileName)
		}
		common.Logger.Infof("Saved a test fixture file for party %d: %s", index, fixtureFileName)
	} else {
		common.Logger.Infof("Fixture file already exists for party %d; not re-creating: %s", index, fixtureFileName)
	}
}

func LoadData(qty, fixtureCount int, id string) ([]keygen.LocalPartySaveData, tss.SortedPartyIDs, error) {
	keys := make([]keygen.LocalPartySaveData, 0, qty)
	plucked := make(map[int]interface{}, qty)
	for i := 0; len(plucked) < qty; i = (i + 1) % fixtureCount {
		_, have := plucked[i]
		if pluck := rand.Float32() < 0.5; !have && pluck {
			plucked[i] = new(struct{})
		}
	}
	for i := range plucked {
		fixtureFilePath := makeTestFixtureFilePath(i, id)
		bz, err := ioutil.ReadFile(fixtureFilePath)
		if err != nil {
			return nil, nil, errors.Wrapf(err,
				"could not open the test fixture for party %d in the expected location: %s. run keygen tests first.",
				i, fixtureFilePath)
		}
		var key keygen.LocalPartySaveData
		if err = json.Unmarshal(bz, &key); err != nil {
			return nil, nil, errors.Wrapf(err,
				"could not unmarshal fixture data for party %d located at: %s",
				i, fixtureFilePath)
		}
		keys = append(keys, key)
	}
	partyIDs := make(tss.UnSortedPartyIDs, len(keys))
	j := 0
	for i := range plucked {
		key := keys[j]
		pMoniker := fmt.Sprintf("%d", i+1)
		partyIDs[j] = tss.NewPartyID(pMoniker, pMoniker, key.ShareID)
		j++
	}
	sortedPIDs := tss.SortPartyIDs(partyIDs)
	sort.Slice(keys, func(i, j int) bool { return keys[i].ShareID.Cmp(keys[j].ShareID) == -1 })
	return keys, sortedPIDs, nil
}

func LoadKeygenTest(qty int, id string, optionalStart ...int) ([]keygen.LocalPartySaveData, tss.SortedPartyIDs, error) {
	keys := make([]keygen.LocalPartySaveData, 0, qty)
	start := 0
	if 0 < len(optionalStart) {
		start = optionalStart[0]
	}
	for i := start; i < qty; i++ {
		fixtureFilePath := makeTestFixtureFilePath(i, id)
		bz, err := ioutil.ReadFile(fixtureFilePath)
		if err != nil {
			return nil, nil, errors.Wrapf(err,
				"could not open the test fixture for party %d in the expected location: %s. run keygen tests first.",
				i, fixtureFilePath)
		}
		var key keygen.LocalPartySaveData
		if err = json.Unmarshal(bz, &key); err != nil {
			return nil, nil, errors.Wrapf(err,
				"could not unmarshal fixture data for party %d located at: %s",
				i, fixtureFilePath)
		}
		keys = append(keys, key)
	}
	partyIDs := make(tss.UnSortedPartyIDs, len(keys))
	for i, key := range keys {
		pMoniker := fmt.Sprintf("%d", i+start+1)
		partyIDs[i] = tss.NewPartyID(pMoniker, pMoniker, key.ShareID)
	}
	sortedPIDs := tss.SortPartyIDs(partyIDs)
	return keys, sortedPIDs, nil
}

func SaveCertificates(cert []byte, name string, id string) {
	certFileName := makeTestCertFilePath(name, id)

	fi, err := os.Stat(certFileName)
	if !(err == nil && fi != nil && !fi.IsDir()) {
		fd, err := os.OpenFile(certFileName, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
		if err != nil {
			common.Logger.Errorf("unable to open certificate file %s for writing", certFileName)
		}
		_, err = fd.Write(cert)
		if err != nil {
			common.Logger.Fatalf("unable to write to certificate file %s", certFileName)
		}
		common.Logger.Infof("Saved a certificate file for CA %s ", name)
	} else {
		common.Logger.Infof("Certificate file already exists for CA %s; not re-creating: %s", name, certFileName)
	}
}

func IsEmptyDir(name string) (bool, error) {
	entries, err := ioutil.ReadDir(name)
	if err != nil {
		return false, err
	}
	return len(entries) == 0, nil
}

// LoadLeafCertificate loads leaf certificate into an *x509.Certificate from  a PEM file on disk.
func LoadLeafCertificate(certFileName string) (*x509.Certificate, error) {
	certPEM, err := ioutil.ReadFile(certFileName)
	if err != nil {
		return nil, fmt.Errorf("can't read file %s: %s", certFileName, err)
	}

	block, _ := pem.Decode(certPEM)
	if block == nil {
		return nil, fmt.Errorf("failed to parse certificate PEM")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse certificate: " + err.Error())
	}
	return cert, nil
}

// LoadCertificates loads one or more certificates into an []*x509.Certificate from a PEM file on disk.
func LoadCertificates(path string) ([]*x509.Certificate, error) {
	rest, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var certs []*x509.Certificate
	for blockno := 0; ; blockno++ {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			continue
		}

		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("unable to parse certificate in block %d: %v", blockno, err)
		}
		certs = append(certs, cert)
	}

	if len(certs) == 0 {
		return nil, fmt.Errorf("no certificates found in file")
	}

	return certs, nil
}

// NewCertPool creates a new *x509.CertPool based on the certificates given
// as parameters.
func NewCertPool(certs ...*x509.Certificate) *x509.CertPool {
	certPool := x509.NewCertPool()
	for _, cert := range certs {
		certPool.AddCert(cert)
	}
	return certPool
}

// LoadCertPool loads one or more certificates into an *x509.CertPool from
// a PEM file on disk.
func LoadCertPool(path string) (*x509.CertPool, error) {
	certs, err := LoadCertificates(path)
	if err != nil {
		return nil, err
	}
	return NewCertPool(certs...), nil
}

func CalculateIdHash(id *big.Int) string {
	sum := sha1.Sum(id.Bytes())
	return hex.EncodeToString(sum[:])
}

func GenerateRandId() *big.Int {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return nil
	}
	var bigI big.Int
	return bigI.SetBytes(b)
}
