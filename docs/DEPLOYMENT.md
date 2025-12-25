# Deployment Checklist

## 1) Go Version

- Use Go **1.25.5+** on all build and runtime environments.
- Align CI Go version with production to avoid stdlib vuln mismatches.

## 2) Policy Sync (Required)

- Server must expose `PolicyBundle()` to clients.
- Clients must include `vk_id` and `params_version` in verification requests.
- Server must enforce `vk_id` and `params_version` before proof verification.

## 3) Challenge Token Keys

- Store HMAC signing keys in KMS/Secrets Manager.
- Rotate keys regularly; use `kid` for key selection during validation.
- Keep a short overlap window (old + new) for rolling deploys.

## 4) RSA Public Key (Delivery Encryption)

- Load delivery RSA public key from KMS/Secrets Manager or env.
- Reject encryption requests if key is missing.

## 5) Key Rotation

- Regenerate proving/verifying keys after circuit changes.
- Publish new `vk_id` and `params_version` via `PolicyBundle`.
- Deprecate old keys with a defined grace period.

## 6) Required Checks

- `govulncheck ./...`
- `go test ./...`
- `make compliance`
