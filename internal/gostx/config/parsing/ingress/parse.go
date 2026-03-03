package ingress

import (
	"github.com/greyhavenhq/greyproxy/internal/gostcore/ingress"
	"github.com/greyhavenhq/greyproxy/internal/gostcore/logger"
	"github.com/greyhavenhq/greyproxy/internal/gostx/config"
	xingress "github.com/greyhavenhq/greyproxy/internal/gostx/ingress"
	"github.com/greyhavenhq/greyproxy/internal/gostx/internal/loader"
)

func ParseIngress(cfg *config.IngressConfig) ingress.Ingress {
	if cfg == nil {
		return nil
	}

	// gRPC/HTTP plugin support removed

	var rules []*ingress.Rule
	for _, rule := range cfg.Rules {
		if rule.Hostname == "" || rule.Endpoint == "" {
			continue
		}

		rules = append(rules, &ingress.Rule{
			Hostname: rule.Hostname,
			Endpoint: rule.Endpoint,
		})
	}
	opts := []xingress.Option{
		xingress.RulesOption(rules),
		xingress.ReloadPeriodOption(cfg.Reload),
		xingress.LoggerOption(logger.Default().WithFields(map[string]any{
			"kind":    "ingress",
			"ingress": cfg.Name,
		})),
	}
	if cfg.File != nil && cfg.File.Path != "" {
		opts = append(opts, xingress.FileLoaderOption(loader.FileLoader(cfg.File.Path)))
	}
	if cfg.HTTP != nil && cfg.HTTP.URL != "" {
		opts = append(opts, xingress.HTTPLoaderOption(loader.HTTPLoader(
			cfg.HTTP.URL,
			loader.TimeoutHTTPLoaderOption(cfg.HTTP.Timeout),
		)))
	}
	return xingress.NewIngress(opts...)
}
