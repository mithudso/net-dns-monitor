# DNS Cache Maintenance (Unbound)

This local resolver implements advanced resilience and security patterns from the `dns-caching` core architecture, including **Serve Stale (RFC 8767)**, **Prefetching**, and **DoT (DNS over TLS)**.

## Operations & Diagnostics

### 1. Checking Status
Verify the service is running:
```bash
sudo brew services info unbound
```

### 2. Validating the Config
If you edit `unbound.conf`, check the repo copy before deploying it (`unbound/install.sh` does this too, and refuses to copy a file that fails):
```bash
unbound-checkconf unbound/unbound.conf
```

### 3. Flushing the Cache
If you need to force a cache clear (e.g., a domain updated its IP but Unbound is serving stale due to our aggressive caching), restart the service:
```bash
sudo brew services restart unbound
```
`unbound-control flush www.example.com` and `unbound-control flush_zone .` flush selectively, but they need a `remote-control:` block with `control-enable: yes`, which `unbound.conf` does not have. Without it they fail to connect.

### 4. Diagnostics (`dig`)
Test local resolution speed. Unbound listens on `192.168.4.1` only, so query that address (it is not listening on `127.0.0.1`):
```bash
dig @192.168.4.1 example.com
```
The first query will take ~20-50ms (fetching via DoT). The second query should take **0ms** (cache hit).

### 5. Log Analysis
If things break, watch the query flow:
```bash
sudo tcpdump -i any port 53
```

## Frontier Concepts Applied
- **Serve Stale (`serve-expired: yes`)**: If your internet drops or upstream fails, this resolver will return the last known good IP from memory.
- **Prefetching**: When a popular domain's TTL drops below 10%, Unbound fetches the update in the background, ensuring clients never wait.
- **QNAME Minimization**: Only the necessary parts of a domain are sent to authoritative servers, improving privacy.
