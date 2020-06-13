package tssInterface

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"math/big"
	"os"

	"golang.org/x/crypto/cryptobyte"
	"golang.org/x/crypto/cryptobyte/asn1"
)

type PrivateKeyCert struct {
	Pk           ecdsa.PublicKey
	Threshold    int
	Participants int
	Id           string
}

func GenerateKey(th, part int, id string) PrivateKeyCert {
	key := GenerateKeys(th, part, id)
	pks := PrivateKeyCert{}
	ecdsaPk := ecdsa.PublicKey{
		Curve: elliptic.P256(),
		X:     key.ECDSAPub.X(),
		Y:     key.ECDSAPub.Y(),
	}
	pks.Pk = ecdsaPk
	pks.Threshold = th
	pks.Participants = part
	pks.Id = id
	return pks
}

func (p *PrivateKeyCert) Public() crypto.PublicKey {
	return &p.Pk
}

func (p *PrivateKeyCert) Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) (signature []byte, err error) {
	msg := &big.Int{}
	msg.SetBytes(digest)

	signatureData := NewSigning(msg, p.Threshold, p.Participants, p.Id)
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

func TssSign(id *big.Int, data []byte) ([]byte, error) {
	KeyLib := make(Library)
	err := KeyLib.LoadLibrary()
	if err != nil || len(KeyLib) == 0 {
		return nil, err
	}

	idHash := CalculateIdHash(id)

	pks := KeyLib[idHash]
	if pks == nil {
		return nil, fmt.Errorf("tssInterface: there is no such Id ")
	}

	signature, err := pks.Sign(rand.Reader, data, nil)
	if err != nil {
		return nil, fmt.Errorf("tssInterface: unable to sign: %s", err)
	}
	return signature, nil
}

type Library map[string]*PrivateKeyCert

const libPath = "/Users/seemenkina/code/tss-lib-test/data/keyLib/key.json"

func (l *Library) LoadLibrary() error {
	bl, err := ioutil.ReadFile(libPath)
	if err != nil {
		return err
	}
	err = json.Unmarshal(bl, l)
	for _, k := range *l {
		k.Pk.Curve = elliptic.P256()
	}
	// if err != nil {
	// 	return err
	// }
	return nil
}

func (l *Library) WriteLibrary() error {
	fi, err := os.Stat(libPath)
	if !(err == nil && fi != nil && !fi.IsDir()) {
		fd, err := os.OpenFile(libPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
		if err != nil {
			return err
		}
		bz, err := json.Marshal(l)
		if err != nil {
			return err
		}
		_, err = fd.Write(bz)
		if err != nil {
			return err
		}
	} else {
		return err
	}
	return nil
}
