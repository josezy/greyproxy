package resolver

import (
	"net"

	"github.com/greyhavenhq/greyproxy/internal/gostcore/logger"
	"github.com/greyhavenhq/greyproxy/internal/gostcore/resolver"
	"github.com/greyhavenhq/greyproxy/internal/gostx/config"
	"github.com/greyhavenhq/greyproxy/internal/gostx/registry"
	xresolver "github.com/greyhavenhq/greyproxy/internal/gostx/resolver"
)

func ParseResolver(cfg *config.ResolverConfig) (resolver.Resolver, error) {
	if cfg == nil {
		return nil, nil
	}

	// gRPC/HTTP plugin support removed

	var nameservers []xresolver.NameServer
	for _, server := range cfg.Nameservers {
		nameservers = append(nameservers, xresolver.NameServer{
			Addr:     server.Addr,
			Chain:    registry.ChainRegistry().Get(server.Chain),
			TTL:      server.TTL,
			Timeout:  server.Timeout,
			ClientIP: net.ParseIP(server.ClientIP),
			Prefer:   server.Prefer,
			Hostname: server.Hostname,
			Async:    server.Async,
			Only:     server.Only,
		})
	}

	return xresolver.NewResolver(
		nameservers,
		xresolver.LoggerOption(
			logger.Default().WithFields(map[string]any{
				"kind":     "resolver",
				"resolver": cfg.Name,
			}),
		),
	)
}
