package direct

import (
	"context"
	"net"

	"github.com/greyhavenhq/greyproxy/internal/gostcore/dialer"
	"github.com/greyhavenhq/greyproxy/internal/gostcore/logger"
	md "github.com/greyhavenhq/greyproxy/internal/gostcore/metadata"
	"github.com/greyhavenhq/greyproxy/internal/gostx/registry"
)

func init() {
	registry.DialerRegistry().Register("direct", NewDialer)
	registry.DialerRegistry().Register("virtual", NewDialer)
}

type directDialer struct {
	logger logger.Logger
}

func NewDialer(opts ...dialer.Option) dialer.Dialer {
	options := &dialer.Options{}
	for _, opt := range opts {
		opt(options)
	}

	return &directDialer{
		logger: options.Logger,
	}
}

func (d *directDialer) Init(md md.Metadata) (err error) {
	return
}

func (d *directDialer) Dial(ctx context.Context, addr string, opts ...dialer.DialOption) (net.Conn, error) {
	return &conn{}, nil
}
