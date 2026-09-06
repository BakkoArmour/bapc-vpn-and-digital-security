# BAPC Root CA Ceremony

This is the procedure for generating the production BAPC Root CA and its first
Intermediate CA. It is a **physical/organizational** procedure — the repository
only supplies the reference cryptographic construction
(`services/trust-core/ceremony.ts`, `x509-forge.ts`) that the ceremony's HSM
operator adapts, plus the `DevKeyProvider` that stands in for the HSM in
non-production environments.

## What the repository does and does not give you

- `services/trust-core/ceremony.ts` (`runDevCeremony`) generates a real,
  chain-verifiable root + intermediate certificate pair for **development,
  CI and staging only**, using in-memory RSA keys. It writes the private keys
  to disk (files prefixed `DEV-ONLY-`) — this is exactly what must never
  happen in production.
- `ForgeX509Builder` builds the certificate TBS bytes and delegates the actual
  signature to an externally-supplied `sign(tbs: Buffer): Promise<Buffer>`
  callback (see `ProtectedKeyProvider`). In production that callback must call
  out to an HSM or cloud KMS's sign operation (PKCS#11 `C_Sign`, AWS CloudHSM,
  Azure Key Vault, GCP Cloud KMS, etc.) — the private key material never
  needs to enter this process. Nothing else in `ForgeX509Builder` changes.

## Before the ceremony

1. Provision the HSM (on-prem HSM appliance or cloud KMS with an HSM-backed
   key ring). Confirm the root key will be generated **inside** the HSM with
   `extractable: false` and requires dual control (no single operator can
   authorize a signing operation alone).
2. Identify at least 3 key custodians and a quorum threshold (e.g., 2-of-3)
   for any future root-key operation (re-issuing the intermediate, rotating
   it, or the (hopefully never-needed) root-key destruction procedure).
3. Prepare an air-gapped machine (no network interface enabled) if the HSM is
   a physical appliance attached over USB/serial rather than a cloud KMS.
4. Have the recording/witnessing process ready: a second person present,
   session recorded or logged, and a signed ceremony record template.

## Ceremony steps

1. **Generate the root key** inside the HSM (RSA-4096 or P-384, per your HSM's
   supported mechanisms). Record the key's HSM identifier/ARN — this is the
   `keyReference` your production `ProtectedKeyProvider` implementation will
   use.
2. **Self-sign the root certificate.** Adapt `runDevCeremony`'s root-signing
   block: build the TBS certificate exactly as `ForgeX509Builder.create` does,
   but pass a `sign` callback that calls the HSM's sign operation with the
   root key reference instead of `DevKeyProvider.sign`.
3. **Generate the intermediate key** inside the HSM (or a separate KMS key
   ring reserved for the intermediate — many deployments keep the root
   completely offline after this step and let the intermediate handle all
   day-to-day issuance).
4. **Sign the intermediate certificate** with the root key, again via the
   HSM's sign operation. `basicConstraints: CA:TRUE` with the intermediate's
   validity window set materially shorter than the root's (the reference
   ceremony uses 5 years vs. 15).
5. **Take the root offline.** After the intermediate is issued, disconnect or
   power down the root HSM/air-gapped machine (or, for a cloud KMS root,
   restrict the root key's IAM policy so only the quorum of custodians can
   invoke a signing operation, and only via a documented change-control
   ticket).
6. **Publish the public certificates.** `root-ca.crt.pem` and
   `intermediate-ca.crt.pem` are public — distribute them to every service
   that must verify BAPC-issued certificates (this repo's
   `TrustCoreIssuer` callers, endpoint agents, mTLS-verifying services).
7. **Record the ceremony.** Capture: date/time, present custodians, HSM
   serial/identifiers, generated key references, certificate serials and
   SHA-256 fingerprints (the reference tool emits these in `manifest.json`),
   and store the signed record per your compliance retention policy.

## Ongoing operation

- The **intermediate** key is what `TrustCoreIssuer` uses for routine node
  certificate issuance (`docs/CODE-ADDENDUM-INTEGRATION.md` step 6: "Connect
  TrustCoreIssuer to the approved HSM/KMS and X.509 builder").
- Certificate revocation (`TrustCoreIssuer.revoke`, `PgCertificateStore`)
  does not require root/intermediate key access — it only marks the database
  record; a CRL/OCSP responder (not yet implemented in this repository) would
  need periodic access to sign a CRL with the intermediate key.
- Rotating the intermediate: repeat steps 3–4 with a new intermediate key
  reference, publish the new intermediate certificate, and keep the old one
  valid until every issued node certificate under it has expired or been
  reissued.

## Never do this in production

- Never generate the root or intermediate private key outside an HSM/KMS.
- Never let `DevKeyProvider` or `runDevCeremony`'s `DEV-ONLY-*.key.pem` files
  exist anywhere production certificates are issued or verified.
- Never allow a single operator to authorize a root-key signing operation.
