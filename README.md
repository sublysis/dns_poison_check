# dns_poison_check.py

A passive auditing tool that estimates how susceptible a recursive DNS resolver is to cache-poisoning (Kaminsky-style) attacks. It measures three independent signals and combines them into a single **0–10 risk score** (0 = very safe, 10 = critical):

1. **Source-port randomization** of the resolver's outbound queries to authoritative servers
2. **Transaction-ID (TXID) randomization** of the same queries
3. **DNSSEC validation** behavior

It sends only ordinary DNS queries and observes real traffic. It never forges or injects spoofed responses and cannot poison a cache by itself.

## Why this needs a "vantage point"

The port and TXID that actually matter are the ones the resolver chooses when it queries *out* to authoritative servers — not anything visible in the answer it hands back to a client. There's no way to observe that from a plain DNS query. The script offers two ways to get a vantage point on that traffic, plus a mode that skips this part entirely:

| Mode | What it does | When to use it | Requirements |
|---|---|---|---|
| `capture` | Sniffs the resolver's own egress traffic live (scapy) while generating load | Testing a resolver **you administer** (your own `unbound`/`dnsmasq`/`BIND`, a box you can SSH into, or a network segment with a SPAN/mirror port) | Run on/near the resolver; root or `CAP_NET_RAW`; `pip install scapy` |
| `authoritative` | Runs a minimal logging listener for a zone delegated to this host, then forces the target resolver to query it | Testing a **third-party/remote** resolver (e.g. during a pentest engagement) where you have no network visibility but do control a domain | A domain with an NS record delegated to this host's public IP; usually root to bind port 53 |
| `dnssec-only` (default) | Skips port/TXID entirely | Neither of the above is available | Nothing extra |

If port/TXID aren't measured, the script **will not fabricate a 0–10 total** — DNSSEC status isn't a valid stand-in for entropy, since most zones still aren't signed and port/TXID randomness matters regardless. It reports the DNSSEC sub-score on its own and tells you what's needed for a full score.

## Install

```bash
pip install dnspython          # always required
pip install scapy              # only needed for --mode capture
```

## Usage

### 1. DNSSEC-only (no special setup)

```bash
python3 dns_poison_check.py 1.1.1.1 --mode dnssec-only
```

Works against any resolver you can reach; no elevated privileges needed. Good first check, and useful on its own since DNSSEC validation is the structural fix that makes port/TXID weaknesses moot *for signed zones*.

### 2. Capture mode — a resolver you administer

Run this **on the resolver's own host** (or a host with visibility into its egress traffic — a SPAN/mirror port, not just a client-facing interface):

```bash
sudo python3 dns_poison_check.py 127.0.0.1 \
  --mode capture \
  --iface eth0 \
  --test-domain example.com \
  --samples 100
```

- `--iface`: the interface where the resolver's *outbound* traffic to authoritative servers actually leaves — not the interface it listens on for client queries.
- `--test-domain`: any domain you're willing to generate load against. The script queries random, never-seen labels under it (e.g. `a1b2c3.example.com`) so every query is a genuine cache miss and forces the resolver to recurse. Use a domain you control if you want to avoid generating traffic toward someone else's authoritative infrastructure.

If the report says `0 samples captured`, it almost always means the capture positioning is wrong (wrong interface, or you're only seeing client→resolver traffic rather than resolver→upstream traffic) — it is **not** treated as a security finding.

### 3. Authoritative mode — a remote/third-party resolver

Requires owning a domain (or a throwaway subdomain) and pointing its NS record at a host you control — a small VPS is enough. On that host:

```bash
sudo python3 dns_poison_check.py 203.0.113.53 \
  --mode authoritative \
  --zone test.yourdomain.example \
  --listen-ip 0.0.0.0 \
  --listen-port 53 \
  --samples 100
```

- `203.0.113.53` here is the **target resolver's IP** (positional argument) — the resolver you're assessing, not this host.
- `--zone`: the domain/subdomain that's NS-delegated to this host's public IP. The script queries the target resolver for random labels under this zone, which forces it to walk the delegation chain and query this host directly — and the script logs the source port and TXID of every query it receives.
- If binding port 53 needs root and that's not available, forward port 53 to a higher port and pass it via `--listen-port`.
- `0 samples captured` here usually means the NS delegation isn't actually pointing at this host, or a firewall is intercepting port 53 before the script's listener sees it.

### JSON output

Add `--json report.json` to any run for a machine-readable version of the full report (useful for feeding into a pentest report or a CI check).

## Reading the score

| Component | Max risk points | What pushes it up |
|---|---|---|
| Source port | 4 | Narrow port range, fixed port, or a step-like/incremental pattern between consecutive queries |
| Transaction ID | 4 | Low entropy, repeated IDs, or a sequential pattern (even one that eventually spans the full 16-bit range — a counter is fully predictable one step ahead regardless of its overall spread, which raw entropy alone can miss) |
| DNSSEC | 2 | 2 = no validation and no DO-bit support; 1 = DO-bit/RRSIG pass-through without actual validation, or inconclusive (test domains unreachable); 0 = validation confirmed |

| Total | Verdict |
|---|---|
| 0–2 | LOW — strong randomization, no classic weaknesses found |
| 2–5 | MODERATE — some weakness present, not trivially exploitable |
| 5–7.5 | HIGH — meaningful weakness in port and/or TXID randomization |
| 7.5–10 | CRITICAL — looks classically vulnerable to blind cache poisoning |

A hundred samples (`--samples 100`, the default) is enough to catch gross issues like a fixed port or sequential IDs. Increase it for a more statistically confident read.

## Things to consider before running it

- **Authorization.** Only point this at a resolver you own or are explicitly authorized to test. For a resolver you don't administer and aren't engaged to test, use the public services instead — [DNS-OARC's Check My DNS](https://cmdns.dns-oarc.net) or [GRC's DNS Spoofability Test](https://www.grc.com/dns/dns.htm) — rather than scripted probing.
- **Where you run it matters.** `capture` mode needs to see the resolver's real egress traffic; running it from the wrong interface, or from a host that isn't actually on-path, silently produces zero samples rather than a wrong-but-plausible answer — check the stderr warnings.
- **Sandboxed/restricted networks can transparently intercept DNS.** Some cloud sandboxes and locked-down networks redirect all outbound port-53 traffic to a fixed resolver regardless of the destination IP you specify, which would make the resolver-targeting logic silently test the wrong thing. If results look identical no matter which IP you pass, check for this before trusting the numbers — a quick way to check is querying an address that shouldn't be routable (e.g. `203.0.113.1`, a documentation-only address) and seeing whether you get a suspiciously fast reply.
- **`authoritative` mode generates real, resolvable-looking DNS traffic** from the target resolver toward infrastructure you control — normal for a diagnostic tool, but be aware it's not purely passive-observation the way `capture` mode is; you're actively causing the resolver to make queries it wouldn't otherwise make (though never forging responses).
- **DNSSEC status and port/TXID entropy are independent.** A resolver can validate DNSSEC perfectly and still have weak port/TXID randomization (which still matters for the majority of zones that aren't signed), or vice versa. Don't treat one as a proxy for the other — this is exactly why the script won't compute a full score from DNSSEC alone.
