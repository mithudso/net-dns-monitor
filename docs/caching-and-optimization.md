# Caching and bounded work

The app has no shared server cache or administrative cache dashboard. Each
process owns its monitor state, histories, worker queues and credential cache.
`docs/ARCHITECTURE.md` describes the timers and data flow; the modules below own
the bounds and persistence policy.

| Area | Contract | Source |
|---|---|---|
| Incident probes | Reachability and DNS share a deadline; injected callables allow offline tests. | `netdnsmonitor/prober.py` |
| Interface probes and throughput | Bind to the selected interface and bound individual operations; caller aggregation has a deadline. | `netdnsmonitor/interface_probe.py`, `netdnsmonitor/throughput.py` |
| Resolution history | Above the 50,000-line compaction trigger, retain each domain's largest comparable elapsed time and newest completed timestamp. NaN is invalid; Infinity keeps the reader's existing stall semantics. Size remains proportional to historical domain cardinality. | `netdnsmonitor/resolution_log.py` |
| Stalled-domain selection | Select domains with recorded stall evidence. The log is historical evidence, not a browser-history cache. | `netdnsmonitor/stall_log.py` |
| Unified log buffers | Limit in-memory retention; a failed read remains distinct from a successful empty read. | `netdnsmonitor/system_log.py`, `netdnsmonitor/query_log.py` |
| Console | Bound execution duration and retained output; terminate child process groups on timeout or quit. | `netdnsmonitor/console.py` |
| Optional developer retrieval | Chroma stores source chunks; Ollama generates embeddings. The optional watcher is independent of the app. | `docs/MCP.md` |

Use the module constants and tests when changing a bound. Compaction must preserve
the evidence consumed by the reader: a domain that stalled historically must not
disappear merely because a later lookup was fast or an elapsed field was invalid.
NaN must not hide a later measured stall during aggregation.

The compaction trigger is not a hard line or byte limit: more than 50,000 distinct
historical domains can still leave more than 50,000 records. A strict retention
limit would need a separate owner decision about preserving ever-stalled evidence.

Run the offline suite after changing concurrency, queue admission or compaction.
Tests establish the bounded-work contract with injected dependencies. They do
not establish current throughput, real VPN behavior, or App Store sandbox access.
