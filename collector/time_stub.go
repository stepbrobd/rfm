//go:build !linux

package collector

import "time"

func bootNow() time.Duration { return 0 }

func suspended() time.Duration { return 0 }
