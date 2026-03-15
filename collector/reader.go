package collector

import "time"

// Reader abstracts the ring buffer for testing and platform isolation.
type Reader interface {
	ReadRawEvent() ([]byte, error)
	SetDeadline(t time.Time)
	DroppedEvents() (uint64, error)
	Close() error
}
