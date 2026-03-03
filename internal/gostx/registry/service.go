package registry

import (
	"github.com/greyhavenhq/greyproxy/internal/gostcore/service"
)

type serviceRegistry struct {
	registry[service.Service]
}
