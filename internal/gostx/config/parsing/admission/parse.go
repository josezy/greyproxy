package admission

import (
	"github.com/greyhavenhq/greyproxy/internal/gostcore/admission"
	"github.com/greyhavenhq/greyproxy/internal/gostcore/logger"
	xadmission "github.com/greyhavenhq/greyproxy/internal/gostx/admission"
	"github.com/greyhavenhq/greyproxy/internal/gostx/config"
	"github.com/greyhavenhq/greyproxy/internal/gostx/internal/loader"
	"github.com/greyhavenhq/greyproxy/internal/gostx/registry"
)

func ParseAdmission(cfg *config.AdmissionConfig) admission.Admission {
	if cfg == nil {
		return nil
	}

	// gRPC/HTTP plugin support removed

	opts := []xadmission.Option{
		xadmission.MatchersOption(cfg.Matchers),
		xadmission.WhitelistOption(cfg.Reverse || cfg.Whitelist),
		xadmission.ReloadPeriodOption(cfg.Reload),
		xadmission.LoggerOption(logger.Default().WithFields(map[string]any{
			"kind":      "admission",
			"admission": cfg.Name,
		})),
	}
	if cfg.File != nil && cfg.File.Path != "" {
		opts = append(opts, xadmission.FileLoaderOption(loader.FileLoader(cfg.File.Path)))
	}
	if cfg.HTTP != nil && cfg.HTTP.URL != "" {
		opts = append(opts, xadmission.HTTPLoaderOption(loader.HTTPLoader(
			cfg.HTTP.URL,
			loader.TimeoutHTTPLoaderOption(cfg.HTTP.Timeout),
		)))
	}

	return xadmission.NewAdmission(opts...)
}

func List(name string, names ...string) []admission.Admission {
	var admissions []admission.Admission
	if adm := registry.AdmissionRegistry().Get(name); adm != nil {
		admissions = append(admissions, adm)
	}
	for _, s := range names {
		if adm := registry.AdmissionRegistry().Get(s); adm != nil {
			admissions = append(admissions, adm)
		}
	}

	return admissions
}
