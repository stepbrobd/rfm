//go:build !linux

package collector

import "time"

func eventTime(ev FlowEvent) time.Time {
	return time.Now()
}
