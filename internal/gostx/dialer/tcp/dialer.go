package tcp

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
	registry.DialerRegistry().Register("tcp", NewDialer)
}

type tcpDialer struct {
	md      metadata
	logger  logger.Logger
	options dialer.Options
}

func NewDialer(opts ...dialer.Option) dialer.Dialer {
	options := dialer.Options{}
	for _, opt := range opts {
		opt(&options)
	}

	return &tcpDialer{
		logger:  options.Logger,
		options: options,
	}
}

func (d *tcpDialer) Init(md md.Metadata) (err error) {
	return d.parseMetadata(md)
}

func (d *tcpDialer) Dial(ctx context.Context, addr string, opts ...dialer.DialOption) (net.Conn, error) {
	var options dialer.DialOptions
	for _, opt := range opts {
		opt(&options)
	}

	conn, err := options.Dialer.Dial(ctx, "tcp", addr)
	if err != nil {
		d.logger.Error(err)
	}

	conn = proxyproto.WrapClientConn(
		d.options.ProxyProtocol,
		xctx.SrcAddrFromContext(ctx),
		xctx.DstAddrFromContext(ctx),
		conn)

	return conn, err
}
