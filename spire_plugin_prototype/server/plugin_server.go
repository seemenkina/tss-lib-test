package server

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"text/template"

	"github.com/hashicorp/hcl"
	"github.com/seemenkina/tss-lib-test/spire_plugin_prototype/plugin"
	"github.com/seemenkina/tss-lib-test/utils"
	"github.com/spiffe/spire/pkg/common/catalog"
	"github.com/spiffe/spire/pkg/server/plugin/nodeattestor"
	"github.com/spiffe/spire/proto/spire/common"
	spi "github.com/spiffe/spire/proto/spire/common/plugin"
)

const (
	pluginName = "tss-nodeattestor"
)

func BuiltIn() catalog.Plugin {
	return builtin(New())
}

func builtin(p *TssPlugin) catalog.Plugin {
	return catalog.MakePlugin(pluginName,
		nodeattestor.PluginServer(p),
	)
}

type Config struct {
	CABundlePath      string `hcl:"ca_bundle_path"`
	AgentPathTemplate string `hcl:"agent_path_template"`
}

type TssConfig struct {
	trustDomain  string
	trustBundle  *x509.CertPool
	pathTemplate *template.Template
}

type TssPlugin struct {
	m      sync.Mutex
	config *TssConfig
}

func New() *TssPlugin {
	return &TssPlugin{}
}

func (t *TssPlugin) Attest(stream nodeattestor.NodeAttestor_AttestServer) error {
	if t.config == nil {
		return errors.New("tssPlugin: plugin not configured")
	}

	req, err := stream.Recv()
	if err != nil {
		return err
	}

	if dataType := req.AttestationData.Type; dataType != pluginName {
		return fmt.Errorf("tssPlugin: unexpected attestation data type %q", dataType)
	}

	attestationData := new(plugin.AttestationData)
	if err := json.Unmarshal(req.AttestationData.Data, attestationData); err != nil {
		return fmt.Errorf("tssPlugin: failed to unmarshal attestation data: %v", err)
	}

	// build up leaf certificate and list of intermediates
	if len(attestationData.Certificates) == 0 {
		return fmt.Errorf("tssPlugin: no certificate to attest")
	}
	leaf, err := x509.ParseCertificate(attestationData.Certificates[0])
	if err != nil {
		return fmt.Errorf("tssPlugin: unable to parse leaf certificate: %v", err)
	}
	intermediates := x509.NewCertPool()
	for i, intermediateBytes := range attestationData.Certificates[1:] {
		intermediate, err := x509.ParseCertificate(intermediateBytes)
		if err != nil {
			return fmt.Errorf("tssPlugin: unable to parse intermediate certificate %d: %v", i, err)
		}
		intermediates.AddCert(intermediate)
	}

	// verify the chain of trust
	chains, err := leaf.Verify(x509.VerifyOptions{
		Intermediates: intermediates,
		Roots:         t.config.trustBundle,
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	})
	if err != nil {
		return fmt.Errorf("certificate verification failed: %v", err)
	}

	challenge, err := plugin.GenerateChallenge(leaf)
	if err != nil {
		return fmt.Errorf("unable to generate challenge: %v", err)
	}

	challengeBytes, err := json.Marshal(challenge)
	if err != nil {
		return fmt.Errorf("tssPlugin: unable to marshal challenge response: %v", err)
	}

	if err := stream.Send(&nodeattestor.AttestResponse{
		Challenge: challengeBytes,
	}); err != nil {
		return fmt.Errorf("tssPlugin: unable to send challenge response: %v", err)
	}

	responseReq, err := stream.Recv()
	if err != nil {
		return err
	}

	response := new(plugin.ECDSASignatureResponse)
	if err := json.Unmarshal(responseReq.Response, response); err != nil {
		return fmt.Errorf("unable to unmarshal challenge response: %v", err)
	}

	if err := plugin.VerifyChallengeResponse(leaf.PublicKey, challenge, response); err != nil {
		return fmt.Errorf("challenge response verification failed: %v", err)
	}

	spiffeID, err := plugin.MakeSpiffeID(t.config.trustDomain, t.config.pathTemplate, leaf)
	if err != nil {
		return fmt.Errorf("failed to make spiffe id: %v", err)
	}

	return stream.Send(&nodeattestor.AttestResponse{
		AgentId:   spiffeID,
		Selectors: buildSelectors(leaf, chains),
	})
}

func (t *TssPlugin) Configure(ctx context.Context, req *spi.ConfigureRequest) (*spi.ConfigureResponse, error) {
	config := new(Config)
	if err := hcl.Decode(config, req.Configuration); err != nil {
		return nil, fmt.Errorf("tssPlugin: unable to decode configuration: %v", err)
	}

	if req.GlobalConfig == nil {
		return nil, errors.New("tssPlugin: global configuration is required")
	}
	if req.GlobalConfig.TrustDomain == "" {
		return nil, errors.New("tssPlugin: trust_domain is required")
	}

	trustBundle, err := utils.LoadCertPool(config.CABundlePath)
	if err != nil {
		return nil, fmt.Errorf("unable to load trust bundle: %v", err)
	}

	pathTemplate := plugin.DefaultAgentPathTemplate
	if len(config.AgentPathTemplate) > 0 {
		tmpl, err := template.New("agent-path").Parse(config.AgentPathTemplate)
		if err != nil {
			return nil, fmt.Errorf("failed to parse agent svid template: %q", config.AgentPathTemplate)
		}
		pathTemplate = tmpl
	}

	t.setConfiguration(&TssConfig{
		trustDomain:  req.GlobalConfig.TrustDomain,
		trustBundle:  trustBundle,
		pathTemplate: pathTemplate,
	})

	return &spi.ConfigureResponse{}, nil
}

func (*TssPlugin) GetPluginInfo(context.Context, *spi.GetPluginInfoRequest) (*spi.GetPluginInfoResponse, error) {
	return &spi.GetPluginInfoResponse{}, nil
}

func (t *TssPlugin) getConfiguration() *TssConfig {
	t.m.Lock()
	defer t.m.Unlock()
	return t.config
}

func (t *TssPlugin) setConfiguration(c *TssConfig) {
	t.m.Lock()
	defer t.m.Unlock()
	t.config = c
}

func buildSelectors(leaf *x509.Certificate, chains [][]*x509.Certificate) []*common.Selector {
	var selectors []*common.Selector

	if leaf.Subject.CommonName != "" {
		selectors = append(selectors, &common.Selector{
			Type: "tssPlugin", Value: "subject:cn:" + leaf.Subject.CommonName,
		})
	}

	// Used to avoid duplicating selectors.
	fingerprints := map[string]*x509.Certificate{}
	for _, chain := range chains {
		// Iterate over all the certs in the chain (skip leaf at the 0 index)
		for _, cert := range chain[1:] {
			fp := plugin.Fingerprint(cert)
			// If the same fingerprint is generated, continue with the next certificate, because
			// a selector should have been already created for it.
			if _, ok := fingerprints[fp]; ok {
				continue
			}
			fingerprints[fp] = cert

			selectors = append(selectors, &common.Selector{
				Type: "tss-nodeattestor", Value: "ca:fingerprint:" + fp,
			})
		}
	}

	return selectors
}
