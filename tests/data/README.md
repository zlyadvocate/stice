# tests/data — test-only PKI

These files exist so `tests/test_tls_transport.cpp` can run a TLS client/server
handshake hermetically, without a network certificate authority or a system
trust store:

| File | Purpose |
|------|---------|
| `tls_test_ca.pem` | Test root CA certificate (`CA:TRUE`, `keyCertSign`) |
| `tls_test_ca_key.pem` | Test root CA private key |
| `tls_test_cert.pem` | Leaf certificate (`CA:FALSE`, `serverAuth`, SAN `DNS:localhost,IP:127.0.0.1`) |
| `tls_test_key.pem` | Leaf private key |

**These keys are public and must never be used outside the test suite.** They are
committed on purpose (hermetic tests beat a generate-at-build-time step), the CA
expires on its own, and nothing here is trusted by any shipped configuration.
If you copy this directory into a deployment, you have handed out a CA key —
generate a real one instead.
