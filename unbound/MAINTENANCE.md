# DNS Cache Maintenance (Unbound)

This local resolver implements advanced resilience and security patterns from the `dns-caching` core architecture, including **Serve Stale (RFC 8767)**, **Prefetching**, and **DoT (DNS over TLS)**.

## Operations & Diagnostics

### 1. Checking Status
Verify the service is running:
```bash
sudo brew services info unbound
```

### 2. Validating the Config
If you edit `unbound.conf`:
```bash
unbound-checkconf
```

### 3. Flushing the Cache
If you need to force a cache clear (e.g., a domain updated its IP but Unbound is serving stale due to our aggressive caching):
```bash
unbound-control flush www.example.com
```
To flush everything:
```bash
unbound-control flush_zone .
```

### 4. Diagnostics (`dig`)
Test local resolution speed:
```bash
dig @127.0.0.1 example.com
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
