package main

import "time"

// a scrape gathers and encodes every series, tens of MiB at the fleet's
// series count, which the endpoint must not let clients multiply
const (
	// metricsInFlight lets a scraper and an operator's curl gather at the
	// same time, further scrapes are refused with 503 until one is done
	metricsInFlight = 2
	// metricsTimeout bounds a gather, past it the scrape gets a 503
	metricsTimeout = 30 * time.Second
	// metricsReadHeaderTimeout bounds the request headers of a client that sends them slowly
	metricsReadHeaderTimeout = 10 * time.Second
	// metricsWriteSlack is the write time a response gets past the gather, so the write timeout outlasts metricsTimeout
	metricsWriteSlack = 30 * time.Second
	// metricsIdleTimeout ends a keep-alive connection no scrape used for two minutes
	metricsIdleTimeout = 2 * time.Minute
)

// shutdownTimeout bounds the metrics server's graceful shutdown on stop
const shutdownTimeout = 5 * time.Second
