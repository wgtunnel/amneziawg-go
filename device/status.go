package device

type StatusCode int32

const (
	StatusHealthy          StatusCode = 0
	StatusHandshakeFailure StatusCode = 1
)
