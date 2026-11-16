# Synthetic loopback TLS conformance

Follow-up to the bounded HTTP transport in PR #27, based on published commit
10c48664e782ff069cc90aef211075e54610edda. This adds tests only, with no production
transport or trust configuration change. Issues #9/#1 and live acceptance remain
open. The earlier HTTP evidence remains scoped to its original tests; this file
records the new synthetic TLS evidence separately.

## What is real and what is substituted

`tests/test_slack_tls.py` starts bounded local TLS servers and exercises the actual
`_connect_tls`, `_exchange`, spawned `_bounded` runner and public transport error
boundary. Certificate signatures, TLS handshake, SNI, hostname checks, encryption,
HTTP bytes and subprocess cleanup use real Python/OpenSSL implementations.

A test-only connector replaces DNS answers with a synthetic public address, routes
that socket exclusively to 127.0.0.1 and supplies a private test SSLContext. That
context retains CERT_REQUIRED and hostname verification, and trusts only a fresh
synthetic CA. Spawned cases apply these scoped mocks in the child; direct connector cases apply
them in the parent test process while the loopback server thread runs. They are
not a production API or persistent configuration. Production certificate defaults and DNS/SSRF policy are
unchanged. This is not evidence of reaching or authenticating real Slack, its
certificates, DNS answers, account credentials, actual host trust roots or network.

An already-installed `openssl` executable creates a one-day CA and signed leaf
certificates in a TemporaryDirectory. The valid leaf covers the logical Slack
hostname used by the existing request codec; the wrong-host leaf covers a synthetic
invalid hostname. A separate empty client trust context tests untrusted-CA failure.
No certificate or private key is committed, installed into an OS/browser trust
store, printed, uploaded or retained for ongoing access. Temporary files, sockets,
server threads and child processes are cleaned on success, failure and cancellation.
Missing OpenSSL fails explicitly rather than installing a dependency or skipping
coverage. Certificate commands have 15-second bounds; listeners and joins are bounded.

## Independent observations

- A valid verified channel reaches the credential callback before HTTP emission.
  The server independently observes exact SNI and one Bearer-bearing HTTP request.
- Wrong hostname and untrusted CA fail with actual SSLCertVerificationError codes.
  Separate subprocess/public-entrypoint cases prove the credential provider is
  never called, no HTTP request is observed and no child survives.
- A raw listener deliberately stalls the handshake. A direct real-socket test
  observes a TLS ClientHello, no bearer canary and a handshake timeout. A separate
  spawned deadline test permits zero connects when startup consumes the budget,
  and always verifies no credential lookup, HTTP request or leaked worker.
- Cancellation after verified TLS but before request emission remains sanitized
  and produces no HTTP request or leaked child.

The server's recorded plaintext is synthetic test content only. TLS handshake
success does not prove the scoped token belongs to an authorized Slack account,
that sharing authority remains valid remotely, or that an effect was delivered.
No production provider or Core acceptance receipt is constructed.

## Reproduction

Run `python3 -m unittest discover -s tests -p test_slack_tls.py -v` and repeat with
`python3 -O`. Then run the repository aggregate and complete optimized suite using
the existing pinned quality tools. The observed generator is OpenSSL 3.5.7 and
Python is 3.12.14; test certificates are regenerated rather than distributed.
No installation, external call, system setting, service or standing job is needed.
