package tcp

import (
	"context"
	"net"
	"time"

	"github.com/greyhavenhq/greyproxy/internal/gostcore/limiter"
	"github.com/greyhavenhq/greyproxy/internal/gostcore/listener"
	"github.com/greyhavenhq/greyproxy/internal/gostcore/logger"
	md "github.com/greyhavenhq/greyproxy/internal/gostcore/metadata"
	admission "github.com/greyhavenhq/greyproxy/internal/gostx/admission/wrapper"
	xnet "github.com/greyhavenhq/greyproxy/internal/gostx/internal/net"
	"github.com/greyhavenhq/greyproxy/internal/gostx/internal/net/proxyproto"
	climiter "github.com/greyhavenhq/greyproxy/internal/gostx/limiter/conn/wrapper"
	limiter_wrapper "github.com/greyhavenhq/greyproxy/internal/gostx/limiter/traffic/wrapper"
	metrics "github.com/greyhavenhq/greyproxy/internal/gostx/metrics/wrapper"
	stats "github.com/greyhavenhq/greyproxy/internal/gostx/observer/stats/wrapper"
	"github.com/greyhavenhq/greyproxy/internal/gostx/registry"
)

func init() {
	registry.ListenerRegistry().Register("tcp", NewListener)
}

type tcpListener struct {
	ln      net.Listener
	logger  logger.Logger
	md      metadata
	options listener.Options
}

func NewListener(opts ...listener.Option) listener.Listener {
	options := listener.Options{}
	for _, opt := range opts {
		opt(&options)
	}
	return &tcpListener{
		logger:  options.Logger,
		options: options,
	}
}

func (l *tcpListener) Init(md md.Metadata) (err error) {
	if err = l.parseMetadata(md); err != nil {
		return
	}

	network := "tcp"
	if xnet.IsIPv4(l.options.Addr) {
		network = "tcp4"
	}

	lc := net.ListenConfig{}
	if l.md.mptcp {
		lc.SetMultipathTCP(true)
		l.logger.Debugf("mptcp enabled: %v", lc.MultipathTCP())
	}
	ln, err := lc.Listen(context.Background(), network, l.options.Addr)
	if err != nil {
		return
	}

	l.logger.Debugf("pp: %d", l.options.ProxyProtocol)

	ln = proxyproto.WrapListener(l.options.ProxyProtocol, ln, 10*time.Second)
	ln = metrics.WrapListener(l.options.Service, ln)
	ln = stats.WrapListener(ln, l.options.Stats)
	ln = admission.WrapListener(l.options.Service, l.options.Admission, ln)
	ln = limiter_wrapper.WrapListener(l.options.Service, ln, l.options.TrafficLimiter)
	ln = climiter.WrapListener(l.options.ConnLimiter, ln)
	l.ln = ln

	return
}

func (l *tcpListener) Accept() (conn net.Conn, err error) {
	conn, err = l.ln.Accept()
	if err != nil {
		return
	}

	conn = limiter_wrapper.WrapConn(
		conn,
		l.options.TrafficLimiter,
		conn.RemoteAddr().String(),
		limiter.ScopeOption(limiter.ScopeConn),
		limiter.ServiceOption(l.options.Service),
		limiter.NetworkOption(conn.LocalAddr().Network()),
		limiter.SrcOption(conn.RemoteAddr().String()),
	)

	return
}

func (l *tcpListener) Addr() net.Addr {
	return l.ln.Addr()
}

func (l *tcpListener) Close() error {
	return l.ln.Close()
}
