package registry

import (
	"github.com/greyhavenhq/greyproxy/internal/gostcore/dialer"
	"github.com/greyhavenhq/greyproxy/internal/gostcore/logger"
)

type NewDialer func(opts ...dialer.Option) dialer.Dialer

type dialerRegistry struct {
	registry[NewDialer]
}

func (r *dialerRegistry) Register(name string, v NewDialer) error {
	if err := r.registry.Register(name, v); err != nil {
		logger.Default().Fatal(err)
	}
	return nil
}
