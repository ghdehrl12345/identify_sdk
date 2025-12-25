# Security Policy

## Supported Versions

We provide security updates for the latest minor release only. Older releases may not receive fixes.

## Reporting a Vulnerability

Please use one of the following channels:
- GitHub Security Advisories (preferred): create a private advisory in this repository.
- If you cannot use GitHub, contact the maintainers privately before public disclosure.

We aim to acknowledge within 48 hours and provide a remediation plan within 7 days for confirmed issues.

## Security Notes

- Proofs bind to a server-issued challenge; issue a fresh challenge for every login attempt to prevent replay.
- Secrets (password) and birth year stay client-side; only commitments and Groth16 proofs travel over the network.
- Regenerate and commit `auth/user.pk`, `auth/user.vk`, `age/age.pk`, `age/age.vk` whenever the circuits change; stale keys will break verification.
- Configure current year and age limits from server policy rather than hard-coding when integrating into production.
- Consider rotating proving/verifying keys when updating circuits or after long-term use.
- Manage secrets (if any) via your KMS and ensure transport is protected via TLS.
- Keep the proving/verifying key fingerprints aligned (`auth.ProvingKeyID`, `auth.VerifyingKeyID`, `age.AgeProvingKeyID`, `age.AgeVerifyingKeyID`); reject mismatched versions.
- Ensure client and server use the same policy inputs (`TargetYear`, `LimitAge`); policy drift will fail verification.
