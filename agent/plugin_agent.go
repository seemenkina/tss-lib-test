package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"strings"
	"sync"

	"github.com/hashicorp/hcl"
	"github.com/seemenkina/tss-lib-test/plugin"
	"github.com/seemenkina/tss-lib-test/tssInterface"
	"github.com/spiffe/spire/pkg/agent/plugin/nodeattestor"
	"github.com/spiffe/spire/pkg/common/catalog"
	"github.com/spiffe/spire/proto/spire/common"
	spi "github.com/spiffe/spire/proto/spire/common/plugin"
)

const (
	pluginName = "tssNodeattestor"
)

func BuiltIn() catalog.Plugin {
	return builtin(New())
}

func builtin(p *TssPlugin) catalog.Plugin {
	return catalog.MakePlugin(pluginName,

		nodeattestor.PluginServer(p),
	)
}

type TssConfig struct {
	trustDomain               string
	X509CertificatePath       string `hcl:"certificate_path"`
	X509IntermediatesCertPath string `hcl:"intermediates_path"`
}

type TssPlugin struct {
	m      sync.Mutex
	config *TssConfig
}

func New() *TssPlugin {
	return &TssPlugin{}
}

func (t *TssPlugin) FetchAttestationData(stream nodeattestor.NodeAttestor_FetchAttestationDataServer) error {
	attestData, id, err := t.loadConfigData()
	if err != nil {
		return err
	}

	// send the attestation data back to the agent
	if err := stream.Send(&nodeattestor.FetchAttestationDataResponse{
		AttestationData: attestData,
	}); err != nil {
		return fmt.Errorf("tssPlugin: failed to send attestation data: %v", err)
	}

	// receive challenge
	resp, err := stream.Recv()
	if err != nil {
		return fmt.Errorf("tssPlugin: failed to receive challenge: %v", err)
	}

	challenge := new(plugin.ECDSASignatureChallenge)
	if err := json.Unmarshal(resp.Challenge, challenge); err != nil {
		return fmt.Errorf("tssPlugin: unable to unmarshal challenge: %v", err)
	}

	// calculate and send the challenge response
	response, err := plugin.CalculateResponse(challenge, id)
	if err != nil {
		return fmt.Errorf("tssPlugin: failed to calculate challenge response: %v", err)
	}

	responseBytes, err := json.Marshal(response)
	if err != nil {
		return fmt.Errorf("tssPlugin: unable to marshal challenge response: %v", err)
	}

	if err := stream.Send(&nodeattestor.FetchAttestationDataResponse{
		Response: responseBytes,
	}); err != nil {
		return fmt.Errorf("tssPlugin: unable to send challenge response: %v", err)
	}

	return nil

}

func (t *TssPlugin) Configure(ctx context.Context, req *spi.ConfigureRequest) (*spi.ConfigureResponse, error) {
	config := new(TssConfig)
	if err := hcl.Decode(config, req.Configuration); err != nil {
		return nil, fmt.Errorf("tssPlugin: unable to decode configuration: %v", err)
	}

	if req.GlobalConfig == nil {
		return nil, errors.New("tssPlugin: global configuration is required")
	}
	if req.GlobalConfig.TrustDomain == "" {
		return nil, errors.New("tssPlugin: trust_domain is required")
	}
	config.trustDomain = req.GlobalConfig.TrustDomain

	if config.X509CertificatePath == "" {
		return nil, fmt.Errorf("tssPlugin: path to certificate required: %s ", req.Configuration)
	}

	// make sure the configuration produces valid data
	if _, _, err := loadData(config); err != nil {
		return nil, err
	}

	t.setConfiguration(config)

	return &spi.ConfigureResponse{}, nil
}

func (t *TssPlugin) GetPluginInfo(context.Context, *spi.GetPluginInfoRequest) (*spi.GetPluginInfoResponse, error) {
	return &spi.GetPluginInfoResponse{}, nil
}

func main() {
	p := New()
	catalog.PluginMain(
		catalog.MakePlugin(pluginName, nodeattestor.PluginServer(p)),
	)
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

func (t *TssPlugin) loadConfigData() (*common.AttestationData, *big.Int, error) {
	config := t.getConfiguration()
	if config == nil {
		return nil, nil, errors.New("tssPlugin: not configured")
	}
	return loadData(config)
}

func loadData(config *TssConfig) (*common.AttestationData, *big.Int, error) {
	leafCert, err := tssInterface.LoadLeafCertificate(config.X509CertificatePath)
	if err != nil {
		return nil, nil, fmt.Errorf("tssPlugin: unable to load leaf certificate %s: ", err)
	}

	var certificates [][]byte
	certificates = append(certificates, leafCert.Raw)

	// Append intermediate certificates if IntermediatesPath is set.
	if strings.TrimSpace(config.X509IntermediatesCertPath) != "" {
		intermediates, err := tssInterface.LoadCertificates(config.X509IntermediatesCertPath)
		if err != nil {
			return nil, nil, fmt.Errorf("tssPlugin: unable to load intermediate certificates: %v", err)
		}

		for _, interCert := range intermediates {
			certificates = append(certificates, interCert.Raw)
		}
	}

	attestationDataBytes, err := json.Marshal(plugin.AttestationData{
		Certificates: certificates,
	})
	if err != nil {
		return nil, nil, fmt.Errorf("tssPlugin: unable to marshal attestation data: %v", err)
	}

	return &common.AttestationData{
		Type: pluginName,
		Data: attestationDataBytes,
	}, leafCert.SerialNumber, nil
}
