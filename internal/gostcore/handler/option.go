package handler

import (
	"crypto/tls"
	"net/url"

	"github.com/greyhavenhq/greyproxy/internal/gostcore/auth"
	"github.com/greyhavenhq/greyproxy/internal/gostcore/bypass"
	"github.com/greyhavenhq/greyproxy/internal/gostcore/chain"
	"github.com/greyhavenhq/greyproxy/internal/gostcore/limiter/rate"
	"github.com/greyhavenhq/greyproxy/internal/gostcore/limiter/traffic"
	"github.com/greyhavenhq/greyproxy/internal/gostcore/logger"
	"github.com/greyhavenhq/greyproxy/internal/gostcore/metadata"
	"github.com/greyhavenhq/greyproxy/internal/gostcore/observer"
	"github.com/greyhavenhq/greyproxy/internal/gostcore/recorder"
)

type Options struct {
	Bypass      bypass.Bypass
	Router      chain.Router
	Auth        *url.Userinfo
	Auther      auth.Authenticator
	RateLimiter rate.RateLimiter
	Limiter     traffic.TrafficLimiter
	TLSConfig   *tls.Config
	Logger      logger.Logger
	Observer    observer.Observer
	Recorders   []recorder.RecorderObject
	Service     string
	Netns       string
}

type Option func(opts *Options)

func BypassOption(bypass bypass.Bypass) Option {
	return func(opts *Options) {
		opts.Bypass = bypass
	}
}

func RouterOption(router chain.Router) Option {
	return func(opts *Options) {
		opts.Router = router
	}
}

func AuthOption(auth *url.Userinfo) Option {
	return func(opts *Options) {
		opts.Auth = auth
	}
}

func AutherOption(auther auth.Authenticator) Option {
	return func(opts *Options) {
		opts.Auther = auther
	}
}

func RateLimiterOption(limiter rate.RateLimiter) Option {
	return func(opts *Options) {
		opts.RateLimiter = limiter
	}
}

func TrafficLimiterOption(limiter traffic.TrafficLimiter) Option {
	return func(opts *Options) {
		opts.Limiter = limiter
	}
}

func TLSConfigOption(tlsConfig *tls.Config) Option {
	return func(opts *Options) {
		opts.TLSConfig = tlsConfig
	}
}

func LoggerOption(logger logger.Logger) Option {
	return func(opts *Options) {
		opts.Logger = logger
	}
}

func ObserverOption(observer observer.Observer) Option {
	return func(opts *Options) {
		opts.Observer = observer
	}
}

func RecordersOption(recorders ...recorder.RecorderObject) Option {
	return func(o *Options) {
		o.Recorders = recorders
	}
}

func ServiceOption(service string) Option {
	return func(opts *Options) {
		opts.Service = service
	}
}

func NetnsOption(netns string) Option {
	return func(opts *Options) {
		opts.Netns = netns
	}
}

type HandleOptions struct {
	Metadata metadata.Metadata
}

type HandleOption func(opts *HandleOptions)

func MetadataHandleOption(md metadata.Metadata) HandleOption {
	return func(opts *HandleOptions) {
		opts.Metadata = md
	}
}
