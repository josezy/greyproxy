package sd

import (
	"github.com/greyhavenhq/greyproxy/internal/gostcore/sd"
	"github.com/greyhavenhq/greyproxy/internal/gostx/config"
)

func ParseSD(cfg *config.SDConfig) sd.SD {
	if cfg == nil {
		return nil
	}

	// gRPC/HTTP plugin support removed
	return nil
}
