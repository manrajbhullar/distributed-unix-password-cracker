#!/usr/bin/env bash

USERNAME="manraj"
PASSWORD="aca"
OUT="shadow"

SHA_ROUNDS=1000
BCRYPT_COST=4   # lowest

rm -f "$OUT"

echo "Generating shadow file..."

pw() {
    printf "%s" "$PASSWORD"
}

YESCRYPT=$(pw | mkpasswd --method=yescrypt -s)
echo "${USERNAME}_yescrypt:${YESCRYPT}:19000:0:99999:7:::" >> "$OUT"

BCRYPT=$(htpasswd -bnBC "$BCRYPT_COST" "" "$PASSWORD" | tr -d ':\n')
echo "${USERNAME}_bcrypt:${BCRYPT}:19000:0:99999:7:::" >> "$OUT"

SHA256=$(pw | mkpasswd --method=sha-256 --rounds="$SHA_ROUNDS" -s)
echo "${USERNAME}_sha256:${SHA256}:19000:0:99999:7:::" >> "$OUT"

SHA512=$(pw | mkpasswd --method=sha-512 --rounds="$SHA_ROUNDS" -s)
echo "${USERNAME}_sha512:${SHA512}:19000:0:99999:7:::" >> "$OUT"

MD5=$(pw | mkpasswd --method=md5 -s)
echo "${USERNAME}_md5:${MD5}:19000:0:99999:7:::" >> "$OUT"

echo "Done."
echo "Created $OUT"
cat "$OUT"
