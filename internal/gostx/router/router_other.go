//go:build !linux

package router

import (
	"github.com/greyhavenhq/greyproxy/internal/gostcore/router"
)

func (*localRouter) setSysRoutes(routes ...*router.Route) error {
	return nil
}
