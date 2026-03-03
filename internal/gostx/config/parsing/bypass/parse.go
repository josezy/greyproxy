package bypass

import (
	"github.com/greyhavenhq/greyproxy/internal/gostcore/bypass"
	"github.com/greyhavenhq/greyproxy/internal/gostcore/logger"
	xbypass "github.com/greyhavenhq/greyproxy/internal/gostx/bypass"
	"github.com/greyhavenhq/greyproxy/internal/gostx/config"
	"github.com/greyhavenhq/greyproxy/internal/gostx/internal/loader"
	"github.com/greyhavenhq/greyproxy/internal/gostx/registry"
)

func ParseBypass(cfg *config.BypassConfig) bypass.Bypass {
	if cfg == nil {
		return nil
	}

	// gRPC/HTTP plugin support removed

	opts := []xbypass.Option{
		xbypass.MatchersOption(cfg.Matchers),
		xbypass.WhitelistOption(cfg.Reverse || cfg.Whitelist),
		xbypass.ReloadPeriodOption(cfg.Reload),
		xbypass.LoggerOption(logger.Default().WithFields(map[string]any{
			"kind":   "bypass",
			"bypass": cfg.Name,
		})),
	}
	if cfg.File != nil && cfg.File.Path != "" {
		opts = append(opts, xbypass.FileLoaderOption(loader.FileLoader(cfg.File.Path)))
	}
	if cfg.HTTP != nil && cfg.HTTP.URL != "" {
		opts = append(opts, xbypass.HTTPLoaderOption(loader.HTTPLoader(
			cfg.HTTP.URL,
			loader.TimeoutHTTPLoaderOption(cfg.HTTP.Timeout),
		)))
	}

	return xbypass.NewBypass(opts...)
}

func List(name string, names ...string) []bypass.Bypass {
	var bypasses []bypass.Bypass
	if bp := registry.BypassRegistry().Get(name); bp != nil {
		bypasses = append(bypasses, bp)
	}
	for _, s := range names {
		if bp := registry.BypassRegistry().Get(s); bp != nil {
			bypasses = append(bypasses, bp)
		}
	}
	return bypasses
}
