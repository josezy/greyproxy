package registry

import (
	"github.com/greyhavenhq/greyproxy/internal/gostcore/logger"
)

type loggerRegistry struct {
	registry[logger.Logger]
}

func (r *loggerRegistry) Register(name string, v logger.Logger) error {
	return r.registry.Register(name, v)
}
