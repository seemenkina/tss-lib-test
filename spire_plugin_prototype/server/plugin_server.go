package server

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sync"

	"github.com/hashicorp/hcl"
	"github.com/spiffe/spire/pkg/common/catalog"
	"github.com/spiffe/spire/pkg/server/plugin/nodeattestor"
	"github.com/spiffe/spire/proto/spire/common"
	spi "github.com/spiffe/spire/proto/spire/common/plugin"
)

const (
	pluginName = "tss-node-attestor"
)

func BuiltIn() catalog.Plugin {
	return builtin(New())
}

func builtin(p *TssPlugin) catalog.Plugin {
	return catalog.MakePlugin(pluginName,
		nodeattestor.PluginServer(p),
	)
}

type ChallengeResponse struct {
}

type TssConfig struct {
	trustDomain string
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

	attestationData := new(common.AttestationData)
	if err := json.Unmarshal(req.AttestationData.Data, attestationData); err != nil {
		return fmt.Errorf("tssPlugin: failed to unmarshal attestation data: %v", err)
	}

	// TODO: Verify Attestation Data

	// TODO: calculate and send the challenge

	var challenge []byte

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

	response := new(ChallengeResponse)
	if err := json.Unmarshal(responseReq.Response, response); err != nil {
		return fmt.Errorf("unable to unmarshal challenge response: %v", err)
	}

	// TODO: Verify challenge response

	// TODO: Make SPIFFE ID
	return stream.Send(&nodeattestor.AttestResponse{
		AgentId:   nil,
		Selectors: nil, // buildSelectors(leaf, chains)",
	})
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

	t.config = config

	return &spi.ConfigureResponse{}, nil
}

func (*TssPlugin) GetPluginInfo(context.Context, *spi.GetPluginInfoRequest) (*spi.GetPluginInfoResponse, error) {
	return &spi.GetPluginInfoResponse{}, nil
}
