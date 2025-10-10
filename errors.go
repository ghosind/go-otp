package otp

import (
	"errors"
)

var (
	// ErrUnsupportedAlgorithm is returned when an unsupported algorithm is requested.
	ErrUnsupportedAlgorithm = errors.New("unsupported algorithm")
)
