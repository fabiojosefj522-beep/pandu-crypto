# pandu-crypto format

**Português:** esta é a especificação exata do formato, para quem quiser implementar o pandu-crypto em outra linguagem. Os [vetores de teste](test/vectors.json) trazem entradas fixas e as saídas esperadas. Já existem versões prontas em [Python](examples/python/pandu_crypto.py) e em [Java/Kotlin](examples/java/PanduCrypto.java), conferidas com esses vetores a cada mudança.

**English:** this is the exact wire format, for anyone implementing pandu-crypto in another language. The [test vectors](test/vectors.json) hold fixed inputs and the expected outputs. Ready-made versions in [Python](examples/python/pandu_crypto.py) and [Java/Kotlin](examples/java/PanduCrypto.java) are checked against them on every change.

## 1. Encodings

- **Base32:** RFC 4648 alphabet `A–Z 2–7`, most significant bit first, **no padding**. The last group is padded with zero bits.
- **Base64url:** RFC 4648 §5 alphabet (`-` and `_`), **no padding**.

## 2. Card identity

| Field | Bytes | Encoding | Length | Where it goes |
|---|---|---|---|---|
| `id` | 10 random | base32 | 16 chars | the QR link (and the server) |
| `key` | 16 random (AES-128, default) or 32 (AES-256) | base32 | 26 or 52 chars | **only** the QR link, after `#` |
| `tok` (edit token) | 32 random | base64url | 43 chars | **only** the owner's device |

Use a cryptographically secure random generator for all three.

## 3. Link

```
<base without fragment>#D=<id><key>
```

Parse with `#D=([A-Z2-7]{16})([A-Z2-7]{26}|[A-Z2-7]{52})$`. The key is in the URL fragment, which browsers never send to servers. Base32 keeps the id and key in the QR code's compact alphanumeric mode, so the QR stays small.

## 4. Plaintext

```
plaintext = flag (1 byte) || body
flag 0: body = the UTF-8 JSON text
flag 1: body = raw DEFLATE (RFC 1951, no zlib or gzip header) of the UTF-8 JSON text
```

Writers may pick whichever is smaller. Readers must accept both.

## 5. Encryption

- **Algorithm:** AES-GCM (NIST SP 800-38D), 128-bit or 256-bit key (the key length tells which).
- **IV:** 12 random bytes, new on **every** save. Never reuse an IV with the same key.
- **Tag:** 128 bits, appended to the ciphertext (the Web Crypto, Python `cryptography` and Java default).
- **Associated data:** none.
- **Output:** `ct = base64url(ciphertext || tag)`, `iv = base64url(iv)` (16 chars).

Decryption must fail closed: a wrong key or any changed byte makes AES-GCM reject the message, and the reader shows nothing.

## 6. Reference server API

The server never receives the key. It stores `{id, ct, iv, u (last update, ISO 8601), h}`, where `h` is the lowercase hex **SHA-256 of the token string** (the 43 ASCII characters, not the decoded bytes).

| Request | Body | Answers |
|---|---|---|
| `GET /api/q?id=ID` | | `200 {ct, iv, u}` · `404` never saved · `410` turned off |
| `PUT /api/q` | `{id, tok, ct, iv}` | `200 {ok, u}` · `400` · `403` another owner · `413` · `429` |
| `DELETE /api/q` | `{id, tok}` | `200 {ok}` (the ciphertext is erased, the id keeps answering `410`) · `403` |

The owner check compares hashes in constant time. A first `PUT` claims the id; later writes need the same token.

## 7. Test vectors

[`test/vectors.json`](test/vectors.json) has base32 and base64url cases (including RFC 4648's), a link, a token hash, and three AES-GCM cases (128-bit raw JSON, 128-bit DEFLATE, 256-bit raw JSON), each with the key, the IV, the exact plaintext bytes and the expected ciphertext. An implementation is compatible when it:

1. decrypts every `ct` to exactly `json`, and
2. encrypts `plaintext_hex` with `key` and `iv` to exactly `ct`.
