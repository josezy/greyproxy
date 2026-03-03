package chain

import (
	"github.com/greyhavenhq/greyproxy/internal/gostcore/chain"
	"github.com/greyhavenhq/greyproxy/internal/gostcore/hop"
	"github.com/greyhavenhq/greyproxy/internal/gostcore/logger"
	"github.com/greyhavenhq/greyproxy/internal/gostcore/metadata"
	xchain "github.com/greyhavenhq/greyproxy/internal/gostx/chain"
	"github.com/greyhavenhq/greyproxy/internal/gostx/config"
	hop_parser "github.com/greyhavenhq/greyproxy/internal/gostx/config/parsing/hop"
	mdx "github.com/greyhavenhq/greyproxy/internal/gostx/metadata"
	"github.com/greyhavenhq/greyproxy/internal/gostx/registry"
)

func ParseChain(cfg *config.ChainConfig, log logger.Logger) (chain.Chainer, error) {
	if cfg == nil {
		return nil, nil
	}

	chainLogger := log.WithFields(map[string]any{
		"kind":  "chain",
		"chain": cfg.Name,
	})

	var md metadata.Metadata
	if cfg.Metadata != nil {
		md = mdx.NewMetadata(cfg.Metadata)
	}

	c := xchain.NewChain(cfg.Name,
		xchain.MetadataChainOption(md),
		xchain.LoggerChainOption(chainLogger),
	)

	for _, ch := range cfg.Hops {
		var hop hop.Hop
		var err error

		if ch.Nodes != nil || ch.Plugin != nil {
			if hop, err = hop_parser.ParseHop(ch, log); err != nil {
				return nil, err
			}
		} else {
			hop = registry.HopRegistry().Get(ch.Name)
		}
		if hop != nil {
			c.AddHop(hop)
		}
	}

	return c, nil
}
