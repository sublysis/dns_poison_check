#!/usr/bin/env python3
"""
dns_poison_check.py — DNS cache-poisoning susceptibility auditor

Measures three things about a RECURSIVE resolver and combines them into a
single 0-10 risk score (0 = very safe, 10 = critical):

  1. Source-port randomization  of the resolver's OUTBOUND upstream queries
  2. Transaction-ID randomization of the same queries
  3. DNSSEC validation behavior

WHY TWO DATA-COLLECTION MODES
------------------------------
The port and TXID that matter for cache poisoning are the ones the
resolver itself chooses when it queries *out* to authoritative servers —
not anything visible in the answer it hands back to you. There is no way
to observe that from a plain DNS client. You need a vantage point on the
resolver's egress traffic. This script offers two:

  --mode capture         Sniff the resolver's own egress live with scapy.
                          Run this ON or NEAR the resolver (same host, or
                          a mirrored/SPAN port) with root / CAP_NET_RAW.
                          Use for a resolver YOU administer.
                          Needs: pip install scapy

  --mode authoritative    Stand up a minimal logging "nameserver" for a
                          zone YOU control and have delegated (NS record)
                          to this host, then fire unique-label queries at
                          the target resolver so it has no choice but to
                          walk out and query YOU — logging exactly which
                          port/TXID it used. This is the same technique
                          DNS-OARC's and GRC's public testers use, and is
                          the practical option for a third-party/remote
                          resolver you have no network visibility into.
                          Needs: a domain, an NS delegation to this host,
                          and (usually) root to bind port 53.

  --mode dnssec-only      Skip port/TXID measurement entirely (default).
                          Useful when neither vantage point above is
                          available; you still get the DNSSEC sub-score.

SCOPE / ETHICS
---------------
This tool is PASSIVE MEASUREMENT ONLY. It sends ordinary DNS queries and
observes real traffic; it never forges or injects spoofed DNS responses
and cannot poison anything by itself. Only point it at resolvers you own
or are explicitly authorized to test — third-party resolvers should be
tested via the public services (DNS-OARC's Check My DNS, GRC's DNS
Spoofability Test) instead of scripted probing.

Requirements: dnspython (always). scapy only if --mode capture.
    pip install dnspython scapy
"""

import argparse
import json
import math
import random
import socket
import string
import struct
import sys
import threading
import time

try:
    import dns.resolver
    import dns.message
    import dns.query
    import dns.rdatatype
    import dns.flags
    import dns.exception
except ImportError:
    sys.exit("Missing dependency: pip install dnspython")


# --------------------------------------------------------------------------
# DNSSEC validation check
# --------------------------------------------------------------------------

# Long-standing, deliberately-broken-signature domains maintained for exactly this kind of test. A resolver that VALIDATES DNSSEC returns SERVFAIL for these; a resolver that doesn't returns a normal answer.
DNSSEC_BROKEN_TEST_DOMAINS = ["dnssec-failed.org", "sigfail.verteiltesysteme.net"]

# A properly-signed domain, used to confirm the resolver at least passes through RRSIG records / sets the DO bit when asked (necessary but not sufficient for validation on its own).
DNSSEC_GOOD_TEST_DOMAIN = "cloudflare.com"


def check_dnssec(resolver_ip, timeout=5):
    result = {
        "validates": None,       # True / False / None (inconclusive)
        "do_bit_supported": False,
        "ad_flag_seen": False,
        "details": [],
    }

    r = dns.resolver.Resolver(configure=False)
    r.nameservers = [resolver_ip]
    r.timeout = timeout
    r.lifetime = timeout

    broken_outcome = None
    for domain in DNSSEC_BROKEN_TEST_DOMAINS:
        try:
            r.resolve(domain, "A")
            broken_outcome = "resolved"
            result["details"].append(
                f"{domain}: resolved normally (resolver did NOT reject the bad signature)"
            )
            break
        except dns.resolver.NoNameservers:
            broken_outcome = "servfail"
            result["details"].append(
                f"{domain}: SERVFAIL (resolver rejected the bad signature — validating)"
            )
            break
        except dns.resolver.NXDOMAIN:
            result["details"].append(f"{domain}: unexpected NXDOMAIN, trying next test domain")
            continue
        except dns.exception.Timeout:
            result["details"].append(f"{domain}: timed out, trying next test domain")
            continue
        except Exception as exc:  # noqa: BLE001 - report and keep going
            result["details"].append(f"{domain}: query error ({exc}), trying next test domain")
            continue

    try:
        q = dns.message.make_query(DNSSEC_GOOD_TEST_DOMAIN, dns.rdatatype.A, want_dnssec=True)
        resp = dns.query.udp(q, resolver_ip, timeout=timeout)
        got_rrsig = any(
            rr.rdtype == dns.rdatatype.RRSIG for rrset in resp.answer for rr in rrset
        )
        ad_flag = bool(resp.flags & dns.flags.AD)
        result["do_bit_supported"] = got_rrsig
        result["ad_flag_seen"] = ad_flag
        result["details"].append(
            f"{DNSSEC_GOOD_TEST_DOMAIN}: RRSIG returned={got_rrsig}, AD flag set={ad_flag}"
        )
    except Exception as exc:  # noqa: BLE001
        result["details"].append(f"{DNSSEC_GOOD_TEST_DOMAIN}: DO-bit test failed ({exc})")

    if broken_outcome == "servfail":
        result["validates"] = True
    elif broken_outcome == "resolved":
        result["validates"] = False
    else:
        result["validates"] = None  # both test domains were unreachable

    return result


def score_dnssec(dnssec_result):
    if dnssec_result["validates"] is True:
        return 0.0, "DNSSEC validation confirmed"
    if dnssec_result["validates"] is False:
        if dnssec_result["do_bit_supported"]:
            return 1.0, "DO bit / RRSIG pass-through works, but resolver does not validate signatures"
        return 2.0, "No DNSSEC validation and no sign of DO-bit support"
    return 1.0, "DNSSEC status inconclusive (test domains unreachable) — scored as partial risk"


# --------------------------------------------------------------------------
# Port / TXID capture: mode "capture" (sniff the resolver's own egress)
# --------------------------------------------------------------------------

def _generate_load(resolver_ip, base_domain, n_samples, per_query_timeout=2):
    """Fire unique-label queries at the resolver to force cache misses,
    which forces it to actually query upstream (generating fresh
    port/TXID choices for us to observe)."""
    r = dns.resolver.Resolver(configure=False)
    r.nameservers = [resolver_ip]
    r.timeout = per_query_timeout
    r.lifetime = per_query_timeout
    for _ in range(n_samples):
        label = "".join(random.choices(string.ascii_lowercase + string.digits, k=12))
        qname = f"{label}.{base_domain}"
        try:
            r.resolve(qname, "A", raise_on_no_answer=False)
        except Exception:
            pass  # expected: NXDOMAIN / timeout. We only care that it queried upstream


def capture_mode(resolver_ip, iface, test_domain, n_samples, timeout):
    try:
        from scapy.all import sniff, IP, UDP, DNS
    except ImportError:
        sys.exit("--mode capture needs scapy: pip install scapy")

    if not test_domain:
        sys.exit("--mode capture needs --test-domain (a real domain the resolver will "
                  "actually recurse for — unique random labels under it must miss cache)")

    captured = []
    stop_event = threading.Event()

    def handle_pkt(pkt):
        if IP in pkt and UDP in pkt and DNS in pkt and pkt[IP].src == resolver_ip:
            dns_layer = pkt[DNS]
            if dns_layer.qr == 0:  # outbound query, not a response
                qname = None
                if dns_layer.qd is not None:
                    try:
                        qname = dns_layer.qd.qname.decode(errors="ignore")
                    except Exception:
                        pass
                captured.append({
                    "port": pkt[UDP].sport,
                    "txid": dns_layer.id,
                    "qname": qname,
                    "ts": time.time(),
                })
                if len(captured) >= n_samples:
                    stop_event.set()

    bpf_filter = f"udp and dst port 53 and src host {resolver_ip}"
    print(f"[capture] sniffing on iface={iface!r} filter={bpf_filter!r}", file=sys.stderr)

    def run_sniff():
        sniff(iface=iface, filter=bpf_filter, prn=handle_pkt,
              stop_filter=lambda p: stop_event.is_set(), timeout=timeout)

    t = threading.Thread(target=run_sniff, daemon=True)
    t.start()
    time.sleep(0.5)  # let the sniffer attach before we start generating traffic

    _generate_load(resolver_ip, test_domain, n_samples)

    t.join(timeout=timeout + 2)
    if not captured:
        print("[capture] WARNING: captured 0 packets. Check that this host actually sees "
              "the resolver's egress traffic on the given interface (not just your own "
              "queries to the resolver's listening port), and that the resolver isn't "
              "just serving everything from cache.", file=sys.stderr)
    return captured


# --------------------------------------------------------------------------
# Port / TXID capture: mode "authoritative" (be the upstream nameserver)
# --------------------------------------------------------------------------

def authoritative_mode(resolver_ip, zone, listen_ip, listen_port, n_samples, timeout):
    if not zone:
        sys.exit("--mode authoritative needs --zone (a domain delegated via NS record "
                  "to this host's public IP)")

    captured = []
    stop_event = threading.Event()

    def server_loop(sock):
        while not stop_event.is_set():
            sock.settimeout(0.5)
            try:
                data, addr = sock.recvfrom(512)
            except socket.timeout:
                continue
            except OSError:
                break
            if len(data) < 12:
                continue
            txid = struct.unpack("!H", data[0:2])[0]
            captured.append({
                "port": addr[1],
                "txid": txid,
                "src_ip": addr[0],
                "ts": time.time(),
            })
            # Deliberately no reply: we have no real zone data to serve, and we only need to see the query hit us once to record port + TXID.
            if len(captured) >= n_samples:
                stop_event.set()

    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.bind((listen_ip, listen_port))
    except PermissionError:
        sys.exit(f"Cannot bind {listen_ip}:{listen_port} — binding port 53 usually needs "
                  f"root, or use --listen-port with a firewall/NAT rule forwarding 53 to it.")
    except OSError as exc:
        sys.exit(f"Cannot bind {listen_ip}:{listen_port}: {exc}")

    print(f"[authoritative] logging queries on {listen_ip}:{listen_port} for zone {zone!r} "
          f"— make sure this host is actually NS-delegated for that zone.", file=sys.stderr)

    t = threading.Thread(target=server_loop, args=(sock,), daemon=True)
    t.start()
    time.sleep(0.5)

    _generate_load(resolver_ip, zone, n_samples)

    stop_event.set()
    t.join(timeout=5)
    sock.close()

    if not captured:
        print("[authoritative] WARNING: captured 0 queries. Check the NS delegation for "
              "the zone actually points at this host's public IP, and that nothing else "
              "(firewall, another service) is intercepting port 53 first.", file=sys.stderr)
    return captured


# --------------------------------------------------------------------------
# Statistics / scoring
# --------------------------------------------------------------------------

def shannon_entropy_ratio(values, lo, hi, n_buckets=64):
    """0 = all samples land in one bucket (no spread), 1 = perfectly uniform across the bucketed range."""
    if not values:
        return 0.0
    width = max((hi - lo + 1) / n_buckets, 1)
    counts = [0] * n_buckets
    for v in values:
        idx = int((v - lo) / width)
        idx = min(max(idx, 0), n_buckets - 1)
        counts[idx] += 1
    total = len(values)
    entropy = 0.0
    for c in counts:
        if c:
            p = c / total
            entropy -= p * math.log2(p)
    max_entropy = math.log2(n_buckets)
    return entropy / max_entropy if max_entropy else 0.0


def sequential_ratio(values_in_arrival_order, max_step=4):
    """Fraction of consecutive samples (in the order they were observed) that differ by a small constant step. Catches simple counters, which can still look 'spread out' by pure entropy once they wrap around, but are trivially predictable one-step-ahead — the property that actually matters for an attacker racing the next guess."""
    vals = values_in_arrival_order
    if len(vals) < 2:
        return 0.0
    hits = sum(1 for a, b in zip(vals, vals[1:]) if 0 < abs(b - a) <= max_step)
    return hits / (len(vals) - 1)


def duplicate_ratio(values):
    if not values:
        return 0.0
    return 1 - (len(set(values)) / len(values))


def score_randomness(values_in_order, lo, hi, label):
    """Returns (risk_points 0-4 or None, summary dict) for one signal (port or txid). None means "not measured", either the mode never attempted collection, or collection ran but captured nothing (a methodology/setup problem, not evidence about the resolver), and must NOT be silently treated as a worst-case finding."""
    n = len(values_in_order)
    if n == 0:
        return None, {"samples": 0, "note": f"no {label} samples captured — not measured"}

    entropy_ratio = shannon_entropy_ratio(values_in_order, lo, hi)
    seq_ratio = sequential_ratio(values_in_order)
    dup_ratio = duplicate_ratio(values_in_order)
    distinct = len(set(values_in_order))

    base = (1 - entropy_ratio) * 4.0
    notes = []

    if seq_ratio > 0.5:
        base = max(base, 3.6)
        notes.append(f"{seq_ratio:.0%} of consecutive samples differ by <=4 — looks incremental/predictable")
    if dup_ratio > 0.3:
        base = max(base, 3.2)
        notes.append(f"{dup_ratio:.0%} duplicate values across {n} samples — small or reused pool")
    if distinct <= max(2, round(n * 0.05)) and n >= 10:
        base = 4.0
        notes.append(f"only {distinct} distinct values across {n} samples — effectively fixed")

    risk_points = round(min(base, 4.0), 2)
    summary = {
        "samples": n,
        "distinct_values": distinct,
        "entropy_ratio": round(entropy_ratio, 3),
        "sequential_ratio": round(seq_ratio, 3),
        "duplicate_ratio": round(dup_ratio, 3),
        "notes": notes,
    }
    return risk_points, summary


def verdict_for(total):
    if total <= 2.0:
        return "LOW — strong randomization, no classic weaknesses found"
    if total <= 5.0:
        return "MODERATE — some weakness present, not trivially exploitable"
    if total <= 7.5:
        return "HIGH — meaningful weakness in port and/or TXID randomization"
    return "CRITICAL — looks classically vulnerable to blind cache poisoning"


def combine_scores(port_score, txid_score, dnssec_score):
    """Only combine components that were actually measured. Port and TXID entropy are independent of DNSSEC status (most zones still aren't signed, so a resolver's port/TXID behavior matters regardless of its DNSSEC posture), extrapolating a full 0-10 score from DNSSEC alone would not be a defensible risk figure, so we refuse to fabricate one. Returns (total_or_None, list_of_measured_component_names)."""
    measured = []
    total = 0.0
    if port_score is not None:
        total += port_score
        measured.append("port")
    if txid_score is not None:
        total += txid_score
        measured.append("txid")
    # dnssec_score is always a number (score_dnssec never returns None)
    total += dnssec_score
    measured.append("dnssec")
    if "port" not in measured or "txid" not in measured:
        return None, measured
    return round(min(total, 10.0), 1), measured


# --------------------------------------------------------------------------
# Report
# --------------------------------------------------------------------------

def _print_component(title, max_points, score, summary):
    if score is None:
        print(f" {title}: NOT MEASURED")
    else:
        print(f" {title}: {score:.2f} / {max_points} risk points")
    for k, v in summary.items():
        if k == "notes":
            for note in v:
                print(f"     ! {note}")
        else:
            print(f"     {k}: {v}")


def print_report(resolver_ip, mode, port_score, port_summary, txid_score, txid_summary,
                  dnssec_score, dnssec_result, dnssec_note):
    total, measured = combine_scores(port_score, txid_score, dnssec_score)

    print("=" * 66)
    print(f" DNS cache-poisoning risk assessment — {resolver_ip}")
    print("=" * 66)
    print(f" Mode: {mode}")
    print()
    _print_component("Source port randomness", 4.0, port_score, port_summary)
    print()
    _print_component("Transaction ID randomness", 4.0, txid_score, txid_summary)
    print()
    print(f" DNSSEC validation        : {dnssec_score:.2f} / 2.0 risk points — {dnssec_note}")
    for d in dnssec_result["details"]:
        print(f"     - {d}")
    print()
    print("-" * 66)
    if total is None:
        print(" TOTAL RISK SCORE: not computed — port and/or TXID randomness was not")
        print(" measured, and DNSSEC status alone is not a defensible stand-in for it")
        print(" (most zones aren't signed, so port/TXID entropy matters regardless).")
        print(" Re-run with --mode capture or --mode authoritative for a full 0-10 score.")
        print(f" DNSSEC-only signal: {dnssec_score:.2f} / 2.0 — {dnssec_note}")
    else:
        print(f" TOTAL RISK SCORE: {total} / 10   ({verdict_for(total)})")
    print("-" * 66)
    return total


# --------------------------------------------------------------------------
# Main
# --------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        description="DNS cache-poisoning susceptibility auditor "
                     "(source-port + TXID randomness, DNSSEC) — passive measurement only.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument("resolver", help="IP address of the recursive resolver to test")
    parser.add_argument("--mode", choices=["capture", "authoritative", "dnssec-only"],
                         default="dnssec-only",
                         help="How to collect port/TXID samples (default: dnssec-only, "
                              "which skips them). See module docstring (-h) for details.")
    parser.add_argument("--iface", help="Interface to sniff on (mode=capture)")
    parser.add_argument("--test-domain",
                         help="Domain to query random labels under, must force real "
                              "upstream recursion (mode=capture)")
    parser.add_argument("--zone", help="Zone delegated to this host (mode=authoritative)")
    parser.add_argument("--listen-ip", default="0.0.0.0", help="Bind address (mode=authoritative)")
    parser.add_argument("--listen-port", type=int, default=53, help="Bind port (mode=authoritative)")
    parser.add_argument("--samples", type=int, default=100, help="Number of query samples to collect")
    parser.add_argument("--timeout", type=int, default=30, help="Overall capture/collection timeout (seconds)")
    parser.add_argument("--json", metavar="FILE", help="Also write the full report as JSON to FILE")
    args = parser.parse_args()

    print(
        "NOTE: passive measurement only — no spoofed packets are sent. "
        "Only test resolvers you own or are authorized to test.\n",
        file=sys.stderr,
    )

    dnssec_result = check_dnssec(args.resolver)
    dnssec_score, dnssec_note = score_dnssec(dnssec_result)

    if args.mode == "capture":
        samples = capture_mode(args.resolver, args.iface, args.test_domain, args.samples, args.timeout)
    elif args.mode == "authoritative":
        samples = authoritative_mode(args.resolver, args.zone, args.listen_ip,
                                      args.listen_port, args.samples, args.timeout)
    else:
        samples = []

    ports_in_order = [s["port"] for s in samples]
    txids_in_order = [s["txid"] for s in samples]

    port_score, port_summary = score_randomness(ports_in_order, 1024, 65535, "port")
    txid_score, txid_summary = score_randomness(txids_in_order, 0, 65535, "TXID")

    total = print_report(args.resolver, args.mode, port_score, port_summary,
                          txid_score, txid_summary, dnssec_score, dnssec_result, dnssec_note)

    if args.json:
        report = {
            "resolver": args.resolver,
            "mode": args.mode,
            "risk_score": total,  # null if port/TXID weren't measured — see risk_score_note
            "risk_score_note": None if total is not None else
                "not computed: port and/or TXID randomness was not measured; "
                "re-run with --mode capture or --mode authoritative for a full score",
            "verdict": verdict_for(total) if total is not None else None,
            "source_port": {"risk_points": port_score, **port_summary},
            "transaction_id": {"risk_points": txid_score, **txid_summary},
            "dnssec": {"risk_points": dnssec_score, "note": dnssec_note, **dnssec_result},
            "raw_samples": samples,
        }
        with open(args.json, "w") as f:
            json.dump(report, f, indent=2)
        print(f"\nFull report written to {args.json}")


if __name__ == "__main__":
    main()