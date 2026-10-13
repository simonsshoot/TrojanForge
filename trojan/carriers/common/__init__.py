"""Shared infrastructure for the carrier subsystem.

Nothing here is itself a payload — these are the benchmark primitives the
carrier generators and self-checks build on:

  honeypot.py — read the planted fake secrets + wrap trojan.judge.patterns
                so a self-check can decide "did the honeypot reach the sink?"
  smtp_sink.py — a tiny local SMTP server that CAPTURES every message in
                memory, so C1 (exfil) runs fully offline: no real mailbox,
                no network. Supports SMTP over SSL (465-style via an
                on-the-fly self-signed cert) and plain SMTP, plus an
                AUTH accept-all (so a generated client that calls .login()
                always succeeds).
  conceal.py  — the concealment primitives the carriers reuse to defeat
                single-file review: name-behavior-isomorphism helpers,
                credential-fragmentation reader/writer, multi-file chain writer.
"""
