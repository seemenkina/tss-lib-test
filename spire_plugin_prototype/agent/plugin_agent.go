package agent

import (
	"context"
	"sync"

	"github.com/spiffe/spire/pkg/agent/plugin/nodeattestor"
	"github.com/spiffe/spire/pkg/common/catalog"
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

func (t *TssPlugin) FetchAttestationData(nodeattestor.NodeAttestor_FetchAttestationDataServer) error {
	panic("implement me")
}

func (t *TssPlugin) Configure(context.Context, *spi.ConfigureRequest) (*spi.ConfigureResponse, error) {
	panic("implement me")
}

func (t *TssPlugin) GetPluginInfo(context.Context, *spi.GetPluginInfoRequest) (*spi.GetPluginInfoResponse, error) {
	return &spi.GetPluginInfoResponse{}, nil
}
