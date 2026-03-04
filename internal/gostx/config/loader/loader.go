package loader

import (
	"github.com/greyhavenhq/greyproxy/internal/gostcore/logger"
	"github.com/greyhavenhq/greyproxy/internal/gostx/config"
	"github.com/greyhavenhq/greyproxy/internal/gostx/config/parsing"
	admission_parser "github.com/greyhavenhq/greyproxy/internal/gostx/config/parsing/admission"
	auth_parser "github.com/greyhavenhq/greyproxy/internal/gostx/config/parsing/auth"
	bypass_parser "github.com/greyhavenhq/greyproxy/internal/gostx/config/parsing/bypass"
	hosts_parser "github.com/greyhavenhq/greyproxy/internal/gostx/config/parsing/hosts"
	limiter_parser "github.com/greyhavenhq/greyproxy/internal/gostx/config/parsing/limiter"
	logger_parser "github.com/greyhavenhq/greyproxy/internal/gostx/config/parsing/logger"
	resolver_parser "github.com/greyhavenhq/greyproxy/internal/gostx/config/parsing/resolver"
	service_parser "github.com/greyhavenhq/greyproxy/internal/gostx/config/parsing/service"
	"github.com/greyhavenhq/greyproxy/internal/gostx/registry"
)

var (
	defaultLoader *loader = &loader{}
)

func Load(cfg *config.Config) error {
	return defaultLoader.Load(cfg)
}

type loader struct{}

func (l *loader) Load(cfg *config.Config) error {
	logCfg := cfg.Log
	if logCfg == nil {
		logCfg = &config.LogConfig{}
	}
	logger.SetDefault(logger_parser.ParseLogger(&config.LoggerConfig{Log: logCfg}))

	tlsCfg, err := parsing.BuildDefaultTLSConfig(cfg.TLS)
	if err != nil {
		return err
	}
	parsing.SetDefaultTLSConfig(tlsCfg)

	if err := register(cfg); err != nil {
		return err
	}

	return nil
}

func register(cfg *config.Config) error {
	if cfg == nil {
		return nil
	}

	for name := range registry.LoggerRegistry().GetAll() {
		registry.LoggerRegistry().Unregister(name)
	}
	for _, loggerCfg := range cfg.Loggers {
		if err := registry.LoggerRegistry().Register(loggerCfg.Name, logger_parser.ParseLogger(loggerCfg)); err != nil {
			return err
		}
	}

	for name := range registry.AutherRegistry().GetAll() {
		registry.AutherRegistry().Unregister(name)
	}
	for _, autherCfg := range cfg.Authers {
		if err := registry.AutherRegistry().Register(autherCfg.Name, auth_parser.ParseAuther(autherCfg)); err != nil {
			return err
		}
	}

	for name := range registry.AdmissionRegistry().GetAll() {
		registry.AdmissionRegistry().Unregister(name)
	}
	for _, admissionCfg := range cfg.Admissions {
		if err := registry.AdmissionRegistry().Register(admissionCfg.Name, admission_parser.ParseAdmission(admissionCfg)); err != nil {
			return err
		}
	}

	for name := range registry.BypassRegistry().GetAll() {
		registry.BypassRegistry().Unregister(name)
	}
	for _, bypassCfg := range cfg.Bypasses {
		if err := registry.BypassRegistry().Register(bypassCfg.Name, bypass_parser.ParseBypass(bypassCfg)); err != nil {
			return err
		}
	}

	for name := range registry.ResolverRegistry().GetAll() {
		registry.ResolverRegistry().Unregister(name)
	}
	for _, resolverCfg := range cfg.Resolvers {
		r, err := resolver_parser.ParseResolver(resolverCfg)
		if err != nil {
			return err
		}
		if err := registry.ResolverRegistry().Register(resolverCfg.Name, r); err != nil {
			return err
		}
	}

	for name := range registry.HostsRegistry().GetAll() {
		registry.HostsRegistry().Unregister(name)
	}
	for _, hostsCfg := range cfg.Hosts {
		if err := registry.HostsRegistry().Register(hostsCfg.Name, hosts_parser.ParseHostMapper(hostsCfg)); err != nil {
			return err
		}
	}

	for name := range registry.TrafficLimiterRegistry().GetAll() {
		registry.TrafficLimiterRegistry().Unregister(name)
	}
	for _, limiterCfg := range cfg.Limiters {
		if err := registry.TrafficLimiterRegistry().Register(limiterCfg.Name, limiter_parser.ParseTrafficLimiter(limiterCfg)); err != nil {
			return err
		}
	}

	for name := range registry.ConnLimiterRegistry().GetAll() {
		registry.ConnLimiterRegistry().Unregister(name)
	}
	for _, limiterCfg := range cfg.CLimiters {
		if err := registry.ConnLimiterRegistry().Register(limiterCfg.Name, limiter_parser.ParseConnLimiter(limiterCfg)); err != nil {
			return err
		}
	}

	for name := range registry.RateLimiterRegistry().GetAll() {
		registry.RateLimiterRegistry().Unregister(name)
	}
	for _, limiterCfg := range cfg.RLimiters {
		if err := registry.RateLimiterRegistry().Register(limiterCfg.Name, limiter_parser.ParseRateLimiter(limiterCfg)); err != nil {
			return err
		}
	}

	for name := range registry.ServiceRegistry().GetAll() {
		registry.ServiceRegistry().Unregister(name)
	}
	for _, svcCfg := range cfg.Services {
		svc, err := service_parser.ParseService(svcCfg)
		if err != nil {
			return err
		}
		if svc != nil {
			if err := registry.ServiceRegistry().Register(svcCfg.Name, svc); err != nil {
				return err
			}
		}
	}

	return nil
}
