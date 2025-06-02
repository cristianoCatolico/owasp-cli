package customerrors

import "errors"

var (
	ErrInvalidHostValue = errors.New("invalid host")
	ErrHostUnhealthy    = errors.New("unable to connect to host")
)
