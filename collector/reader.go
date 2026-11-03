package collector

import "time"

// Reader abstracts the ring buffer for testing and platform isolation
// the record ReadRawEvent returns is only valid until the next call
type Reader interface {
	ReadRawEvent() ([]byte, error)
	SetDeadline(t time.Time)
	DroppedEvents() (uint64, error)
	Close() error
}
