package router

import (
	"net"

	"github.com/greyhavenhq/greyproxy/internal/gostcore/logger"
	"github.com/greyhavenhq/greyproxy/internal/gostcore/router"
	"github.com/greyhavenhq/greyproxy/internal/gostx/config"
	"github.com/greyhavenhq/greyproxy/internal/gostx/internal/loader"
	xrouter "github.com/greyhavenhq/greyproxy/internal/gostx/router"
)

func ParseRouter(cfg *config.RouterConfig) router.Router {
	if cfg == nil {
		return nil
	}

	// gRPC/HTTP plugin support removed

	var routes []*router.Route
	for _, route := range cfg.Routes {
		if route == nil {
			continue
		}
		_, ipNet, _ := net.ParseCIDR(route.Net)
		dst := route.Dst
		if dst != "" {
			_, ipNet, _ = net.ParseCIDR(dst)
		} else {
			if ipNet != nil {
				dst = ipNet.String()
			}
		}

		if dst == "" || route.Gateway == "" {
			continue
		}

		routes = append(routes, &router.Route{
			Net:     ipNet,
			Dst:     dst,
			Gateway: route.Gateway,
		})
	}
	opts := []xrouter.Option{
		xrouter.RoutesOption(routes),
		xrouter.ReloadPeriodOption(cfg.Reload),
		xrouter.LoggerOption(logger.Default().WithFields(map[string]any{
			"kind":   "router",
			"router": cfg.Name,
		})),
	}
	if cfg.File != nil && cfg.File.Path != "" {
		opts = append(opts, xrouter.FileLoaderOption(loader.FileLoader(cfg.File.Path)))
	}
	if cfg.HTTP != nil && cfg.HTTP.URL != "" {
		opts = append(opts, xrouter.HTTPLoaderOption(loader.HTTPLoader(
			cfg.HTTP.URL,
			loader.TimeoutHTTPLoaderOption(cfg.HTTP.Timeout),
		)))
	}
	return xrouter.NewRouter(opts...)
}
