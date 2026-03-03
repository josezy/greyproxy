package direct

import (
	"strings"

	mdata "github.com/greyhavenhq/greyproxy/internal/gostcore/metadata"
	mdutil "github.com/greyhavenhq/greyproxy/internal/gostx/metadata/util"
)

type metadata struct {
	action string
}

func (c *directConnector) parseMetadata(md mdata.Metadata) (err error) {
	c.md.action = strings.ToLower(mdutil.GetString(md, "action"))
	return
}
