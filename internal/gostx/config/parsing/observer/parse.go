package observer

import (
	"github.com/greyhavenhq/greyproxy/internal/gostcore/observer"
	"github.com/greyhavenhq/greyproxy/internal/gostx/config"
)

func ParseObserver(cfg *config.ObserverConfig) observer.Observer {
	if cfg == nil {
		return nil
	}

	// gRPC/HTTP plugin support removed
	return nil
}
