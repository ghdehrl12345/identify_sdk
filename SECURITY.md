# Security Notes

- Proofs bind to a server-issued challenge; issue a fresh challenge for every login attempt to prevent replay.
- Secrets (password) and birth year stay client-side; only MiMC commitments and Groth16 proofs travel over the network.
- Regenerate and commit `client/user.pk` and `server/user.vk` whenever the circuit changes; stale keys will break verification.
- Configure current year and age limits from server policy rather than hard-coding when integrating into production.
- Consider rotating proving/verifying keys when updating circuits or after long-term use.
- For vulnerability reports, please open a private security advisory on GitHub or contact the maintainers before public disclosure.
- Manage secrets (if any) via your KMS and ensure transport is protected via TLS; enable application-level logging/monitoring for verification events.
