# Interview notes — Project 1

## The 30-second version

> I built a network IDS pipeline on Suricata — but the part I'd actually talk about
> is the triage layer on top of it. Raw `eve.json` is a firehose: in my sample run,
> alerts were 20% of lines and the rest was flow and protocol metadata. I wrote a
> parser that flattens alerts into a CSV sorted worst-first, ranks top signatures
> and talkers, and returns a non-zero exit code when a severity-1 alert appears so
> it can gate a pipeline. Getting from firehose to "these three things, in this
> order" is the actual L1 job.

Lead with the reduction, not the install. Anyone can `brew install suricata`.

## Specifics worth having ready

**The checksum offload trap.** macOS NICs do checksum offload, so packets reach
Suricata with checksums that look invalid. With `checksum-checks` on, it silently
discards traffic you can see perfectly well in Wireshark. Set `pcap.checksum-checks: no`.
This is a good answer because it is a real, specific bug with a real symptom —
"detection works on PCAP but not live capture."

**Why the brute-force rule uses `threshold`.** One failed SSH connect is noise.
Five from one source in 60 seconds is a pattern. And the counter is keyed `by_src`
so it tracks the attacker — key it `by_dst` and a single noisy scanner suppresses
the rule for every other host on the network.

**Why there's a canary rule.** SID 1000010 fires on a benign request to
`testmynids.org`. If it stops firing, the pipeline is broken. Without it, a dead
sensor and a quiet network produce identical dashboards. This usually gets a
follow-up question, and it is the single best detail in the project.

**Memory tuning, with numbers.** `detect.profile: low`, `stream.memcap: 128mb`,
`reassembly.depth: 1mb`, industrial app-layer parsers disabled. Steady state
400–600 MB on an 8 GB machine. Naming the specific knobs beats "I optimized it."

**Local SID range.** Custom rules live in 1000000–1999999. Reuse an ET sid and
`suricata-update` overwrites it on the next pull — a detection that silently
disappears.

## Questions you will get

**"How do you know it works?"**
Ground-truth-labelled data. CTU-13 ships known-malicious IPs, so detection rate is
computable. I also seeded the synthetic generator, which makes parser behaviour
exactly reproducible — 600 events in, 120 alerts out, every time.

**"What's your false positive rate?"**
Measured against an hour of my own traffic, where every alert is by definition a
false positive. The useful output isn't the number, it's `uniq -c` on the signature
column — two or three rules generate most of the noise. Threshold those and the
rate drops by an order of magnitude without losing coverage.

**"What would you do differently at scale?"**
This is a single sensor writing to a local file. At scale you need: Suricata on a
span/tap rather than a laptop NIC, eve.json shipped to a SIEM rather than parsed
locally, rule deployment through version control with `suricata -T` in CI, and
`community-id` on every event so flows correlate with Zeek and endpoint data. The
config already emits community-id for exactly that reason.

**"What does this NOT catch?"**
Anything encrypted, which is most C2 now. Suricata sees the TLS handshake — SNI,
JA3 — but not the payload. That's the honest limit, and it's why Projects 3 and 4
exist: threat intel on the destination, and endpoint telemetry for what the TLS
tunnel hides. Saying this unprompted signals you understand defence in depth rather
than treating one tool as complete.

**"Severity 1 in Suricata means what?"**
Most severe. Suricata inverts the intuition — 1 is high, 3 is low. The parser keeps
Suricata's convention and adds a `severity_label` column rather than silently
flipping it, because a tool that disagrees with its upstream's numbering is how
incidents get misprioritised.

## Don't claim

- That you detected real attacks, if you ran it on synthetic data. Say "synthetic,
  seeded, so the parser behaviour is reproducible" — that's a strength, stated plainly.
- A specific detection-rate number without naming the dataset it came from.
- That this is production-ready. It's a single-sensor lab, and saying so is what
  makes the rest of your claims credible.
