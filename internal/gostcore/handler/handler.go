package handler

import (
	"context"
	"net"

	"github.com/greyhavenhq/greyproxy/internal/gostcore/hop"
	"github.com/greyhavenhq/greyproxy/internal/gostcore/metadata"
)

type Handler interface {
	Init(metadata.Metadata) error
	Handle(context.Context, net.Conn, ...HandleOption) error
}

type Forwarder interface {
	Forward(hop.Hop)
}
