package agent

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"sync"

	"github.com/hashicorp/hcl"
	"github.com/seemenkina/tss-lib-test/utils"
	"github.com/spiffe/spire/pkg/agent/plugin/nodeattestor"
	"github.com/spiffe/spire/pkg/common/catalog"
	"github.com/spiffe/spire/proto/spire/common"
	spi "github.com/spiffe/spire/proto/spire/common/plugin"
)

const (
	pluginName = "tss-node-attestor"
)

type ChallengeResponse struct {
	Nonce []byte
}

func BuiltIn() catalog.Plugin {
	return builtin(New())
}

func builtin(p *TssPlugin) catalog.Plugin {
	return catalog.MakePlugin(pluginName,

		nodeattestor.PluginServer(p),
	)
}

type TssConfig struct {
	trustDomain           string
	x509CertificatePath   string
	x509CACertificatePath string
	ecdsaKeyGenDataPath   string
}

type TssPlugin struct {
	m sync.Mutex
	c *TssConfig
}

func New() *TssPlugin {
	return &TssPlugin{}
}

func (t *TssPlugin) FetchAttestationData(stream nodeattestor.NodeAttestor_FetchAttestationDataServer) error {

	// TODO: Create Attestation Data: Cert
	// Нужен в конфиге путь до созданного сертификата + путь до root CA(если нет его, то видимо отказ)
	// Плюс нужен путь где хранить часть ключа
	// Если все пусто, то генерим

	configData := t.c
	key, cert := loadData(configData)

	// send the attestation data back to the agent
	if err := stream.Send(&nodeattestor.FetchAttestationDataResponse{
		AttestationData: &common.AttestationData{
			Type: pluginName,
			Data: nil,
		},
	}); err != nil {
		return fmt.Errorf("tssPlugin: failed to send attestation data: %v", err)
	}

	// receive challenge
	resp, err := stream.Recv()
	if err != nil {
		return fmt.Errorf("tssPlugin: failed to receive challenge: %v", err)
	}

	challenge := new(ChallengeResponse)
	if err := json.Unmarshal(resp.Challenge, challenge); err != nil {
		return fmt.Errorf("x509pop: unable to unmarshal challenge: %v", err)
	}

	// TODO: calculate and send the challenge response
	// Генерим свой nonce + server nonce и подписываем ключем

	var response []byte // it should be struct

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

	if config.x509CACertificatePath == "" {
		return nil, errors.New("tssPlugin: path to root CA required")
	}

	t.c = config

	return &spi.ConfigureResponse{}, nil
}

func (t *TssPlugin) GetPluginInfo(context.Context, *spi.GetPluginInfoRequest) (*spi.GetPluginInfoResponse, error) {
	return &spi.GetPluginInfoResponse{}, nil
}

func loadData(config *TssConfig) ([]byte, []byte) {

	fi, err := os.Stat(config.x509CACertificatePath)
	if err != nil && fi == nil {
		// create new
	} else {
		cert, err := utils.LoadCertificate(config.x509CACertificatePath)
		if err != nil {
			return nil, nil
		}
	}
}

func main() {
	p := New()
	catalog.PluginMain(
		catalog.MakePlugin(pluginName, nodeattestor.PluginServer(p)),
	)
}
