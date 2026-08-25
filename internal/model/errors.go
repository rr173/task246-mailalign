package model

import "errors"

var (
	ErrInvalidArgument = errors.New("invalid argument")
	ErrNotFound        = errors.New("not found")
	ErrConflict        = errors.New("conflict")
	ErrInvalidState    = errors.New("invalid state")
	ErrImmutable       = errors.New("immutable")
)
