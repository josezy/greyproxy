package tcp

import (
	md "github.com/greyhavenhq/greyproxy/internal/gostcore/metadata"
	mdutil "github.com/greyhavenhq/greyproxy/internal/gostx/metadata/util"
)

type metadata struct {
	mptcp bool
}

func (l *tcpListener) parseMetadata(md md.Metadata) (err error) {
	l.md.mptcp = mdutil.GetBool(md, "mptcp")

	return
}
