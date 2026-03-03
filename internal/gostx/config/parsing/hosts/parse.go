package hosts

import (
	"net"

	"github.com/greyhavenhq/greyproxy/internal/gostcore/hosts"
	"github.com/greyhavenhq/greyproxy/internal/gostcore/logger"
	"github.com/greyhavenhq/greyproxy/internal/gostx/config"
	xhosts "github.com/greyhavenhq/greyproxy/internal/gostx/hosts"
	"github.com/greyhavenhq/greyproxy/internal/gostx/internal/loader"
)

func ParseHostMapper(cfg *config.HostsConfig) hosts.HostMapper {
	if cfg == nil {
		return nil
	}

	// gRPC/HTTP plugin support removed

	var mappings []xhosts.Mapping
	for _, mapping := range cfg.Mappings {
		if mapping.IP == "" || mapping.Hostname == "" {
			continue
		}

		ip := net.ParseIP(mapping.IP)
		if ip == nil {
			continue
		}
		mappings = append(mappings, xhosts.Mapping{
			Hostname: mapping.Hostname,
			IP:       ip,
		})
	}
	opts := []xhosts.Option{
		xhosts.MappingsOption(mappings),
		xhosts.ReloadPeriodOption(cfg.Reload),
		xhosts.LoggerOption(logger.Default().WithFields(map[string]any{
			"kind":  "hosts",
			"hosts": cfg.Name,
		})),
	}
	if cfg.File != nil && cfg.File.Path != "" {
		opts = append(opts, xhosts.FileLoaderOption(loader.FileLoader(cfg.File.Path)))
	}
	if cfg.HTTP != nil && cfg.HTTP.URL != "" {
		opts = append(opts, xhosts.HTTPLoaderOption(loader.HTTPLoader(
			cfg.HTTP.URL,
			loader.TimeoutHTTPLoaderOption(cfg.HTTP.Timeout),
		)))
	}
	return xhosts.NewHostMapper(opts...)
}
