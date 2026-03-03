package hop

import (
	"strings"

	"github.com/greyhavenhq/greyproxy/internal/gostcore/chain"
	"github.com/greyhavenhq/greyproxy/internal/gostcore/hop"
	"github.com/greyhavenhq/greyproxy/internal/gostcore/logger"
	xbypass "github.com/greyhavenhq/greyproxy/internal/gostx/bypass"
	"github.com/greyhavenhq/greyproxy/internal/gostx/config"
	"github.com/greyhavenhq/greyproxy/internal/gostx/config/parsing"
	bypass_parser "github.com/greyhavenhq/greyproxy/internal/gostx/config/parsing/bypass"
	node_parser "github.com/greyhavenhq/greyproxy/internal/gostx/config/parsing/node"
	selector_parser "github.com/greyhavenhq/greyproxy/internal/gostx/config/parsing/selector"
	xhop "github.com/greyhavenhq/greyproxy/internal/gostx/hop"
	"github.com/greyhavenhq/greyproxy/internal/gostx/internal/loader"
	"github.com/greyhavenhq/greyproxy/internal/gostx/metadata"
	mdutil "github.com/greyhavenhq/greyproxy/internal/gostx/metadata/util"
)

func ParseHop(cfg *config.HopConfig, log logger.Logger) (hop.Hop, error) {
	if cfg == nil {
		return nil, nil
	}

	// gRPC/HTTP plugin support removed

	var ppv int
	var soMark int
	ifce := cfg.Interface
	var netns string
	if cfg.Metadata != nil {
		md := metadata.NewMetadata(cfg.Metadata)
		if v := mdutil.GetString(md, parsing.MDKeyInterface); v != "" {
			ifce = v
		}

		if cfg.SockOpts != nil {
			soMark = cfg.SockOpts.Mark
		}
		if v := mdutil.GetInt(md, parsing.MDKeySoMark); v > 0 {
			soMark = v
		}
		ppv = mdutil.GetInt(md, parsing.MDKeyProxyProtocol)
		netns = mdutil.GetString(md, parsing.MDKeyNetns)
	}

	var nodes []*chain.Node
	for _, v := range cfg.Nodes {
		if v == nil {
			continue
		}

		m := v.Metadata
		if m == nil {
			m = map[string]any{}
			v.Metadata = m
		}
		md := metadata.NewMetadata(m)

		if v.Resolver == "" {
			v.Resolver = cfg.Resolver
		}
		if v.Hosts == "" {
			v.Hosts = cfg.Hosts
		}

		if !md.IsExists(parsing.MDKeyInterface) {
			// inherit from hop
			if ifce != "" {
				m[parsing.MDKeyInterface] = ifce
			}
			// node level
			if v.Interface != "" {
				m[parsing.MDKeyInterface] = v.Interface
			}
		}
		if !md.IsExists(parsing.MDKeySoMark) {
			// inherit from hop
			if soMark != 0 {
				m[parsing.MDKeySoMark] = soMark
			}
			// node level
			if v.SockOpts != nil && v.SockOpts.Mark != 0 {
				m[parsing.MDKeySoMark] = v.SockOpts.Mark
			}
		}
		if !md.IsExists(parsing.MDKeyProxyProtocol) && ppv > 0 {
			// inherit from hop
			m[parsing.MDKeyProxyProtocol] = ppv
		}
		if !md.IsExists(parsing.MDKeyNetns) {
			// inherit from hop
			if netns != "" {
				m[parsing.MDKeyNetns] = netns
			}
			// node level
			if v.Netns != "" {
				m[parsing.MDKeyNetns] = v.Name
			}
		}

		if v.Connector == nil {
			v.Connector = &config.ConnectorConfig{}
		}
		if strings.TrimSpace(v.Connector.Type) == "" {
			v.Connector.Type = "http"
		}

		if v.Dialer == nil {
			v.Dialer = &config.DialerConfig{}
		}
		if strings.TrimSpace(v.Dialer.Type) == "" {
			v.Dialer.Type = "tcp"
		}

		node, err := node_parser.ParseNode(cfg.Name, v, log)
		if err != nil {
			return nil, err
		}
		if node != nil {
			nodes = append(nodes, node)
		}
	}

	sel := selector_parser.ParseNodeSelector(cfg.Selector)
	if sel == nil {
		sel = selector_parser.DefaultNodeSelector()
	}

	opts := []xhop.Option{
		xhop.NameOption(cfg.Name),
		xhop.NodeOption(nodes...),
		xhop.SelectorOption(sel),
		xhop.BypassOption(xbypass.BypassGroup(bypass_parser.List(cfg.Bypass, cfg.Bypasses...)...)),
		xhop.ReloadPeriodOption(cfg.Reload),
		xhop.LoggerOption(log.WithFields(map[string]any{
			"kind": "hop",
			"hop":  cfg.Name,
		})),
	}

	if cfg.File != nil && cfg.File.Path != "" {
		opts = append(opts, xhop.FileLoaderOption(loader.FileLoader(cfg.File.Path)))
	}
	if cfg.HTTP != nil && cfg.HTTP.URL != "" {
		opts = append(opts, xhop.HTTPLoaderOption(loader.HTTPLoader(
			cfg.HTTP.URL,
			loader.TimeoutHTTPLoaderOption(cfg.HTTP.Timeout),
		)))
	}
	return xhop.NewHop(opts...), nil
}
