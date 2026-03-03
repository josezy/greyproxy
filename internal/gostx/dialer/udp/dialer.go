package udp

import (
	"context"
	"net"

	"github.com/greyhavenhq/greyproxy/internal/gostcore/dialer"
	"github.com/greyhavenhq/greyproxy/internal/gostcore/logger"
	md "github.com/greyhavenhq/greyproxy/internal/gostcore/metadata"
	xctx "github.com/greyhavenhq/greyproxy/internal/gostx/ctx"
	"github.com/greyhavenhq/greyproxy/internal/gostx/internal/net/proxyproto"
	"github.com/greyhavenhq/greyproxy/internal/gostx/registry"
)

func init() {
	registry.DialerRegistry().Register("udp", NewDialer)
}

type udpDialer struct {
	md      metadata
	logger  logger.Logger
	options dialer.Options
}

func NewDialer(opts ...dialer.Option) dialer.Dialer {
	options := &dialer.Options{}
	for _, opt := range opts {
		opt(options)
	}

	return &udpDialer{
		logger:  options.Logger,
		options: *options,
	}
}

func (d *udpDialer) Init(md md.Metadata) (err error) {
	return d.parseMetadata(md)
}

func (d *udpDialer) Dial(ctx context.Context, addr string, opts ...dialer.DialOption) (net.Conn, error) {
	var options dialer.DialOptions
	for _, opt := range opts {
		opt(&options)
	}

	c, err := options.Dialer.Dial(ctx, "udp", addr)
	if err != nil {
		return nil, err
	}

	c = &conn{
		UDPConn: c.(*net.UDPConn),
	}

	c = proxyproto.WrapClientConn(
		d.options.ProxyProtocol,
		xctx.SrcAddrFromContext(ctx),
		xctx.DstAddrFromContext(ctx),
		c)

	return c, nil
}
