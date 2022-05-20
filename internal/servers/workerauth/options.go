package workerauth

import (
	"github.com/hashicorp/boundary/internal/db"
)

// getOpts - iterate the inbound Options and return a struct
func getOpts(opt ...Option) options {
	opts := getDefaultOptions()
	for _, o := range opt {
		o(&opts)
	}
	return opts
}

// Option - how Options are passed as arguments
type Option func(*options)

// options = how options are represented
type options struct {
	withLimit  int
	withDbOpts []db.Option
}

func getDefaultOptions() options {
	return options{}
}

// WithLimit provides an option to provide a limit. Intentionally allowing
// negative integers. If WithLimit < 0, then unlimited results are returned. If
// WithLimit == 0, then default limits are used for results.
func WithLimit(limit int) Option {
	return func(o *options) {
		o.withLimit = limit
	}
}

// WithDbOpts passes through given DB options to the DB layer
func WithDbOpts(opts ...db.Option) Option {
	return func(o *options) {
		o.withDbOpts = opts
	}
}
