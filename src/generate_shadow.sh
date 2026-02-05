#!/usr/bin/env bash

USERNAME="manraj"
PASSWORD="abc"
OUT="shadow"

# Cost Settings
SHA_ROUNDS=1000
BCRYPT_COST=4
YESCRYPT_ROUNDS=1

rm -f "$OUT"

echo "Generating shadow file..."

pw() {
    printf "%s" "$PASSWORD"
}

# ---------- yescrypt ----------
YESCRYPT=$(pw | mkpasswd --method=yescrypt --rounds="$YESCRYPT_ROUNDS" -s)
echo "${USERNAME}_yescrypt:${YESCRYPT}:19000:0:99999:7:::" >> "$OUT"

# ---------- bcrypt ----------
BCRYPT=$(htpasswd -bnBC "$BCRYPT_COST" "" "$PASSWORD" | tr -d ':\n')
echo "${USERNAME}_bcrypt:${BCRYPT}:19000:0:99999:7:::" >> "$OUT"

# ---------- sha256 ----------
SHA256=$(pw | mkpasswd --method=sha-256 --rounds="$SHA_ROUNDS" -s)
echo "${USERNAME}_sha256:${SHA256}:19000:0:99999:7:::" >> "$OUT"

# ---------- sha512 ----------
SHA512=$(pw | mkpasswd --method=sha-512 --rounds="$SHA_ROUNDS" -s)
echo "${USERNAME}_sha512:${SHA512}:19000:0:99999:7:::" >> "$OUT"

# ---------- md5 ----------
MD5=$(pw | mkpasswd --method=md5 -s)
echo "${USERNAME}_md5:${MD5}:19000:0:99999:7:::" >> "$OUT"

echo "Done."
echo "Created $OUT"
cat "$OUT"
