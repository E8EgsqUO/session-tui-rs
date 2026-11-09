These certificate and PKCS#8 key fixtures are public, disposable test material.
They are never used by production clients or servers and must never secure a
real service. They let the TLS verifier tests check valid and forged handshake
signatures without network access or an external `openssl` dependency at test
runtime. Certificate validity dates do not matter for these signature-only tests.
