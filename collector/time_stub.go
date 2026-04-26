//go:build !linux

package collector

import "time"

func eventTime(FlowEvent) time.Time {
	return time.Now()
}
