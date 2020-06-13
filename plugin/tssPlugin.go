package plugin

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"
	"text/template"

	"github.com/seemenkina/tss-lib-test/tssInterface"
	"github.com/spiffe/spire/pkg/common/idutil"
)

const (
	nonceLen   = 32
	pluginName = "tssNodeattestor"
)

// DefaultAgentPathTemplate is the default text/template
var DefaultAgentPathTemplate = template.Must(template.New("agent-svid").Parse("{{ .PluginName }}/{{ .Fingerprint }}"))

type agentPathTemplateData struct {
	*x509.Certificate
	Fingerprint string
	PluginName  string
	TrustDomain string
}

type AttestationData struct {
	// DER encoded x509 certificate chain leading back to the trusted root. The
	// leaf certificate comes first.
	Certificates [][]byte `json:"certificates"`
}

type ECDSASignatureChallenge struct {
	// Nonce is the nonce generated by the challenger.
	Nonce []byte `json:"nonce"`
}

type ECDSASignatureResponse struct {
	// Nonce is the nonce generated by the responder.
	Nonce []byte `json:"nonce"`

	// R value of the ECDSA signature of the combined challenger and responder
	// nonces.
	R []byte `json:"r"`

	// S value of the ECDSA signature of the combined challenger and responder
	// nonces.
	S []byte `json:"s"`
}

func GenerateChallenge(cert *x509.Certificate) (*ECDSASignatureChallenge, error) {
	// ensure that the public key is intended to be used for digital signatures
	if (cert.KeyUsage & x509.KeyUsageDigitalSignature) == 0 {
		return nil, errors.New("certificate not intended for digital signature use")
	}

	nonce, err := generateNonce()
	if err != nil {
		return nil, err
	}

	return &ECDSASignatureChallenge{
		Nonce: nonce,
	}, nil
}

func CalculateResponse(challenge *ECDSASignatureChallenge, id *big.Int) (*ECDSASignatureResponse, error) {
	if challenge == nil {
		return nil, errors.New("expecting ECDSA challenge")
	}

	nonce, err := generateNonce()
	if err != nil {
		return nil, err
	}

	combined, err := combineNonces(challenge.Nonce, nonce)
	if err != nil {
		return nil, err
	}

	signature, err := tssInterface.TssSign(id, combined)
	if err != nil {
		return nil, err
	}

	var sign struct {
		R, S *big.Int
	}

	if _, err := asn1.Unmarshal(signature, &sign); err != nil {
		return nil, fmt.Errorf("failed to unmarshal signature data: %v", err)
	}
	return &ECDSASignatureResponse{
		Nonce: nonce,
		R:     sign.R.Bytes(),
		S:     sign.S.Bytes(),
	}, nil
}

func VerifyChallengeResponse(publicKey interface{}, challenge *ECDSASignatureChallenge, response *ECDSASignatureResponse) error {
	pk := publicKey.(*ecdsa.PublicKey)
	if challenge == nil {
		return errors.New("expecting ECDSA challenge")
	}
	if response == nil {
		return errors.New("expecting ECDSA response")
	}
	combined, err := combineNonces(challenge.Nonce, response.Nonce)
	if err != nil {
		return err
	}
	r := new(big.Int)
	r.SetBytes(response.R)
	s := new(big.Int)
	s.SetBytes(response.S)

	if !ecdsa.Verify(pk, combined, r, s) {
		return errors.New("ECDSA signature verify failed")
	}
	return nil
}

func Fingerprint(cert *x509.Certificate) string {
	sum := sha1.Sum(cert.Raw) // nolint: gosec // SHA1 use is according to specification
	return hex.EncodeToString(sum[:])
}

// MakeSpiffeID creates a SPIFFE ID from X.509 Certificate data.
func MakeSpiffeID(trustDomain string, agentPathTemplate *template.Template, cert *x509.Certificate) (string, error) {
	var agentPath bytes.Buffer
	if err := agentPathTemplate.Execute(&agentPath, agentPathTemplateData{
		Certificate: cert,
		PluginName:  pluginName,
		Fingerprint: Fingerprint(cert),
	}); err != nil {
		return "", err
	}

	return idutil.AgentURI(trustDomain, agentPath.String()).String(), nil
}

func generateNonce() ([]byte, error) {
	b := make([]byte, nonceLen)
	if _, err := rand.Read(b); err != nil {
		return nil, err
	}
	return b, nil
}

func combineNonces(challenge, response []byte) ([]byte, error) {
	if len(challenge) != nonceLen {
		return nil, errors.New("invalid challenge nonce")
	}
	if len(response) != nonceLen {
		return nil, errors.New("invalid response nonce")
	}
	h := sha256.New()
	// write the challenge and response and ignore errors since it won't fail
	// writing to the digest
	_, _ = h.Write(challenge)
	_, _ = h.Write(response)
	return h.Sum(nil), nil
}