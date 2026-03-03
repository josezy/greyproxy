package admission

import "context"

type Options struct {
	Service string
}

type Option func(opts *Options)

func WithService(service string) Option {
	return func(opts *Options) {
		opts.Service = service
	}
}

type Admission interface {
	Admit(ctx context.Context, addr string, opts ...Option) bool
}
