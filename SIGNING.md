# Protected firmware release signing

Review preparation only. No signing keys, environment, firmware release or public
manifest were created or changed for this branch. Existing customers continue to
read the unchanged manifest.

The production workflow is manual, runs only on this repository's main branch,
requires the production environment's independent reviewer and prevention of
self-review, and verifies that gate before signing. Inputs are environment data,
never interpolated shell source. It verifies the private dev artifact's measured
hash/size/version, signs those exact bytes without rebuilding, then carries the
signature and security version into the public manifest.

Before any authorized production run, the operator must review key custody and
backup, provision protected customer boards with the corresponding ECDSA P-256
public key, and commit only that public key to `keys/ota-signing-public.pem`.
The production environment needs `FW_PRODUCTION_SIGNING_PRIVATE_KEY` (encrypted
PKCS#8 PEM), `FW_PRODUCTION_SIGNING_KEY_PASSWORD`, narrowly scoped
`DEV_RELEASES_READ` and `GH_FIRMWARE_RELEASES_WRITE`. Never put a private key in
this repository, an argument, artifact, log or listing. The encrypted private key
exists only in a runner temporary file with mode 0600, removed on exit; its
password reaches OpenSSL through stdin. The matching public key is verified by
the signer. A missing gate/key/password or mismatch fails instead of falling back.

Development signing uses a DIFFERENT key held only by the private firmware dev
workflow. Test boards receive only the development public key; customer boards
receive only the production public key. A dev signature never authorizes an
update on a protected customer board. Original unprovisioned boards remain on
the legacy firmware path.

Canonical UTF-8 signed metadata is exactly:

```
GGFW1\nesp32-gopher\n<version>\n<security_version>\n<size>\n<lowercase SHA256>\n
```

Version is a canonical three-part decimal version. Security version is a positive
uint32; size is 1..4194304. Signature is ECDSA P-256/SHA-256, DER encoded as
lowercase hex. URL is intentionally excluded so promotion can preserve the
tested image while moving it to the public release URL. Controller policy still
requires a verified HTTPS origin, exact length/hash, acceptable version and
persisted minimum security version before marking an image bootable.

The signing helper/tests and promotion workflow have a canonical review copy in
the private firmware repository (`scripts/` and `releases/`). Keep those copies
identical when editing. Tests use disposable keys only:

```
python -m unittest discover -s .github/scripts -p 'test_*.py' -v
```

Installing this workflow or configuring secrets does not authorize publishing.
Production dispatch, approval and any manifest change require the owner's
separate explicit authorization.
