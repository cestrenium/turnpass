package codec

import "errors"

var (
	errPaddingOverruns    = errors.New("the padding overruns the frame")
	errPaddingNotZero     = errors.New("the frame's padding is not zero bytes")
	errFrameTooShort      = errors.New("the frame is too short")
	errNoMarker           = errors.New("the frame has no fd 01 marker")
	errBadCompressionFlag = errors.New("the frame names no compression")
	errNotSpaceWrapped    = errors.New("the frame payload is not space-wrapped JSON")
)
