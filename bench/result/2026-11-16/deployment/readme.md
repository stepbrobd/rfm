# Deployment window of rfm 2026.1109.0 on 22 hosts, 2026-11-16

Read-only extraction for the deployment section of the paper. It replaces the
window of `../../2026-11-09/production/` (15 hosts on 2026.1105.0), because the
fleet grew to 22 hosts on 2026-11-15 and every host now runs the release that
the benchmark measures.

## Method

Every number here comes from the host's own VictoriaMetrics, which scrapes the
agent every 30 s, over ssh to the store on loopback. No script scrapes an
agent: rfm shows a new label tuple at zero on its first scrape, to whoever
scrapes first, and a second scraper would take that sample away from the
store. The window of 2026-11-09 did scrape the agents every 60 s for 2.2 hours.

- `fleet.py survey`: release, start times, CPUs and sampling rate per host
  (`*.survey.json`, `survey.md`).
- `fleet.py window`: per host over its window, the agent's CPU and memory, the
  flow table size, ring drops, evictions, the interface counters and the NIC
  driver's counters, from single series (`*.win.json`, `window.md`). The flow
  estimates are summed hour by hour with
  `sum by (direction) (increase_pure(rfm_flow_packets_total[1h]))`, which
  counts a series that is new in the hour from zero and any other series from
  its last sample before the hour. The exact counters of the IP families are
  summed the same way (`tables.md`).
- `fleet.py chain`: the same sums from the store's raw samples
  (`/api/v1/export`), as a check of the hourly queries. On 3 hosts over 2 hours
  the 2 methods agree to the packet (`check/check.md`).
- `show.py` prints the tables.

## Windows

The windows end on 2026-11-16 14:00 UTC and are aligned to the hour
(`plan-all.txt`):

- 14 hosts run 2026.1109.0 since 2026-11-10 11:52 UTC: 146 hours.
- kongo's system generations show the release since 2026-11-14 21:02 UTC: 40
  hours.
- 7 hosts were added on 2026-11-15 between 22:35 and 22:48 UTC: 15 hours.

The sampling rate was 10 on every host for its whole window.

## Results

`window.md` and `tables.md` hold the tables and their summary lines.

- The flow estimate is within 0.31% of the exact count of IP packets on every
  host, received 0.9969 to 1.0015 and sent 0.9996 to 1.0016.
- Each estimate rests on 0.34 to 74 million sampled packets. The column
  "samples" of `tables.md` is `rfm_flow_sampled_packets_total`, which counts
  the wire packets of the sampled skbs, not the sampled skbs. Independent
  sampling of as many packets has a standard error of 0.012 to 0.171%
  (`1/sqrt`), and the largest of the 44 differences is 1.95 of these errors.
  With merged skbs the true error is larger than this figure.
- The agent used 0.16 to 2.41% of one core (median 0.42%) and 43 to 113 MB of
  memory on average (median 73). 16 of the 22 hosts are under 0.6% of a core.
- The flow table held up to 15849 concurrent flows on a host. No host forced an
  eviction or folded a label tuple. One host lost 2210 ring events in 6.1 days.
- Against the NIC driver's counters rfm read 0.9999 to 1.0368 of the packets.
  8 hosts are within 0.3% in both directions. The other 14 are `virtio_net`
  guests on which rfm reads 0.4 to 3.7% above the driver in at least one
  direction. On the `macb` host rfm reads 6.1% more received bytes.

## Notes

- The run also asked for `count(rfm_flow_packets_total)` once per hour. On
  butte, the host with the most label churn, each of these queries took about
  3 s, and the session was stopped after 3 of its 146 hours because the store
  kept one of the host's 2 vCPUs busy. butte's "series max" in `window.md` is
  therefore the maximum of 3 hours. Its estimate and exact sums are complete,
  they ran first. `fleet.py` no longer sends that query.
- The 146 hourly estimate queries took 746 s of query time on butte and 1 to
  117 s on the other hosts.
- The flow record sizes of the 2026-11-09 window (`flowsize_hist.json` there,
  "0.995 of estimated packets in flows of 100 or more samples") are wrong. Its
  script keyed a record on `first_seen`, which the agent derives from a boot
  epoch that it reads anew on every request, so the key of one flow table
  entry changed with every snapshot and each entry was counted once per
  snapshot with its cumulative count.
