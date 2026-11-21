#!/usr/bin/env bash
# Builds the BAPC VPN image with Podman on the bapc-vpn server (no Docker, no GitHub), signs it (sigstore) and
# pushes it to the BAPC Registry, then asks the Registry to promote the digest to the stage it is going to.
# Run as root, ideally detached:
#   systemd-run --unit=bapc-vpn-build --wait --pipe bash build-image.sh /opt/bapc-vpn-releases/bapc-vpn-<sha>.tar.gz <sha> staging|production
#
# Needs, once per machine (see deploy/hosting/README.md):
#   /etc/bapc-vpn/registry-push.json   podman auth file: a BAPC Login client of app bapc-vpn with registry:push registry:promote
#   /etc/bapc-vpn/registry-client.env  REGISTRY_CLIENT_ID / REGISTRY_CLIENT_SECRET of the same client (for the promotion API)
#   /etc/bapc-vpn/signing/sigstore.key (+ sigstore.pass)  made with `skopeo generate-sigstore-key`; its .pub is a trusted
#                                       key in the Registry console. The private key never leaves this machine.
#   /etc/containers/registries.d/registry.bapc.app.yaml   use-sigstore-attachments: true
# Prints the pushed digest on the last line (sha256:...), which deploy/hosting/release.mjs deploys.
set -Eeuo pipefail
BUNDLE=${1:?usage: build-image.sh <bundle.tar.gz> <sha> <staging|production>}
SHA=${2:?sha}
STAGE=${3:?stage}
case "$STAGE" in staging|production) ;; *) echo "stage must be staging or production" >&2; exit 2;; esac
REPO=registry.bapc.app/bapc-vpn/core
ETC=/etc/bapc-vpn
log(){ printf '%s build %s: %s\n' "$(date -u +%FT%TZ)" "$SHA" "$*" >&2; }
for f in "$ETC/registry-push.json" "$ETC/registry-client.env" "$ETC/signing/sigstore.key" "$ETC/signing/sigstore.pass"; do
  [ -s "$f" ] || { log "missing $f (one-time setup in deploy/hosting/README.md)"; exit 1; }
done

CTX=$(mktemp -d /var/tmp/bapc-vpn-build.XXXXXX)
trap 'rm -rf "$CTX"' EXIT
tar -xzf "$BUNDLE" -C "$CTX" --strip-components=1
rm -f "$CTX/deploy/.env"

log "1/4 podman build"
podman build --pull=missing --layers -f "$CTX/deploy/Dockerfile" -t "$REPO:$SHA" \
  --label "org.opencontainers.image.revision=$SHA" --label "org.opencontainers.image.source=bapc/bapc-vpn-and-digital-security" "$CTX" >&2

log "2/4 signing and pushing to the BAPC Registry"
DIGESTFILE="$CTX/digest"
podman push --authfile "$ETC/registry-push.json" \
  --sign-by-sigstore-private-key "$ETC/signing/sigstore.key" --sign-passphrase-file "$ETC/signing/sigstore.pass" \
  --digestfile "$DIGESTFILE" "$REPO:$SHA" >&2
DIGEST=$(cat "$DIGESTFILE")
[[ "$DIGEST" =~ ^sha256:[a-f0-9]{64}$ ]] || { log "push gave no digest"; exit 1; }

log "3/4 checking the Registry has it, with its signature"
set -a; . "$ETC/registry-client.env"; set +a
TOKEN=$(curl -fsS https://bapc.app/oauth/token -d grant_type=client_credentials --data-urlencode "client_id=$REGISTRY_CLIENT_ID" \
  --data-urlencode "client_secret=$REGISTRY_CLIENT_SECRET" -d audience=bapc-registry -d 'scope=registry:pull registry:promote' | node -e 'let s="";process.stdin.on("data",d=>s+=d).on("end",()=>process.stdout.write(JSON.parse(s).access_token||""))')
[ -n "$TOKEN" ] || { log "BAPC Login gave no token for the registry client"; exit 1; }
ART=$(curl -fsS -H "authorization: Bearer $TOKEN" "https://registry.bapc.app/api/v1/artifacts/$DIGEST")
echo "$ART" | node -e 'let s="";process.stdin.on("data",d=>s+=d).on("end",()=>{const a=JSON.parse(s);const sig=a.signature??a.artifact?.signature;console.error("registry: "+JSON.stringify({status:a.status??a.artifact?.status,signature:sig?.status??sig??null}))})'

log "4/4 asking for promotion to $STAGE"
PROMO=$(curl -sS -o /dev/stderr -w '%{http_code}' -H "authorization: Bearer $TOKEN" -H 'content-type: application/json' -H "idempotency-key: $SHA-$STAGE" \
  -d "{\"repository\":\"bapc-vpn/core\",\"digest\":\"$DIGEST\",\"environment\":\"$STAGE\",\"reason\":\"BAPC VPN release $SHA\"}" https://registry.bapc.app/api/v1/promotions)
case "$PROMO" in
  201) log "promoted to $STAGE";;
  202) log "promotion to $STAGE waits for the owner in the Registry console (https://registry.bapc.app/approvals)";;
  *) log "promotion answered $PROMO (see above)"; exit 1;;
esac
echo "$DIGEST"
