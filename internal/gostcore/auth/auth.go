package auth

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

// Authenticator is an interface for user authentication.
type Authenticator interface {
	Authenticate(ctx context.Context, user, password string, opts ...Option) (id string, ok bool)
}
