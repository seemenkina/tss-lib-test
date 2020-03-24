package server

import (
	"context"
	"sync"

	"github.com/spiffe/spire/pkg/common/catalog"
	"github.com/spiffe/spire/pkg/server/plugin/nodeattestor"
	spi "github.com/spiffe/spire/proto/spire/common/plugin"
)

const (
	pluginName = "tss"
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
	trustDomain string
}

type TssPlugin struct {
	m sync.Mutex
	c *TssConfig
}

func New() *TssPlugin {
	return &TssPlugin{}
}

func (p *TssPlugin) Attest(stream nodeattestor.NodeAttestor_AttestServer) error {
	return nil
}

func (p *TssPlugin) Configure(ctx context.Context, req *spi.ConfigureRequest) (*spi.ConfigureResponse, error) {

	return &spi.ConfigureResponse{}, nil
}

func (*TssPlugin) GetPluginInfo(context.Context, *spi.GetPluginInfoRequest) (*spi.GetPluginInfoResponse, error) {
	return &spi.GetPluginInfoResponse{}, nil
}
