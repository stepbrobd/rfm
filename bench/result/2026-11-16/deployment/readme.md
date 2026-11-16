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

## Flow records and series over 2 hours (`flows/`)

A second measurement asks how much of the traffic lies in flow records, and
in the series of a remote AS, that hold enough samples for a useful estimate.
It ran on the 22 hosts on 2026-11-16 from 15:24:40 to 17:24:45 UTC (`start`,
`end`).

- `flowsize.py` takes a snapshot of each agent's flow table every 20 s over
  ssh (`rfm flows top` with a limit above the table size). Every host
  delivered 361 snapshots, none failed, and the longest gap between 2
  snapshots was 20.6 s (`flowsize.log`). An entry stays in the table for 30 s
  after its last packet, so every record is seen after its last packet and
  its last sighting holds its final count. A record is identified by
  interface, direction, protocol, addresses and ports, and a new record under
  the same key by a `first_seen` that moved by more than 5 s. The keys are
  hashed in memory and never written. The files with the counts per record
  stay out of the archive.
- `hist.py` sorts the records by the sampled packets they gained in the
  window and weights them with the estimated packets they gained in the
  window (`flowsize_hist.json`, `flowsize.md`). A record that existed before
  the window counts with its gain since the first snapshot.
- `flowcheck.py` with `fleet.py edges` compares the estimated packets that
  the records of a host gained between its first and its last snapshot with
  the exact IP counters of the same interval, interpolated from the store's
  raw samples (`flowcheck.md`, `edges/`).
- `fleet.py series` with `seriesshow.py` asks each store, over the window of
  the host's snapshots, for the share of the estimated packets in label
  tuples and in remote ASes whose sampled packets reach a threshold
  (`series.md`, `series/`). The remote AS is the source AS of received and the
  destination AS of sent packets. Packets whose remote address has no AS are
  reported apart. These are 16 instant queries per host, and they took at
  most 3.9 s of query time on a host.

Results, as shares of the estimated packets of the 2 hours:

- The check passes. The records' estimate is within 0.47% of the exact count
  on every host and in both directions, where `1/sqrt` of the sampled packets
  is 0.11 to 0.57%. The flow tables and the stores also agree on the total,
  75.29 and 75.31 million estimated packets.
- 1792292 records grew in the window, and 0.06% of them gained 100 or more
  sampled packets.
- Flow records with 100 or more sampled packets carried 43.6% pooled over the
  hosts, and 5.3 to 96.1% per host with a median of 12.8%. 2 hosts are at 50%
  or more. Records with 10 or more carried 68.6% pooled (54.4 to 98.8%, median
  66.0%), and records with 4500 or more carried 37.0% pooled (median 0).
- Label tuples with 100 or more sampled packets carried 93.0% pooled (85.1 to
  99.8% per host, median 95.0%).
- Named remote ASes with 100 or more sampled packets carried 96.4% pooled
  (88.3 to 99.7% per host, median 95.0%). With 4500 or more they carried 66.1%
  pooled (20.2 to 95.6%, median 37.7%). Packets without a remote AS were 1.7%
  pooled and at most 9.9% on a host.
- A host received from 51 to 1446 named ASes in the 2 hours, and 37 to 161 of
  them reached 100 sampled packets.

The thresholds are in sampled wire packets, the unit of the flow table and of
`rfm_flow_sampled_packets_total`. A sampled skb of g packets adds g, so 100
sampled packets are 100 samples for unmerged traffic and fewer under GRO or
TSO. 4500 sampled packets hold at least 100 samples at up to 45 packets per
skb. The agent keeps no count of sampled skbs.

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
  snapshot with its cumulative count. The section above holds the corrected
  measurement, 43.6% in place of 99.5%.
