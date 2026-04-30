# Burp - CryptoChef

CryptoChef decrypts and re-encrypts HTTP request and response bodies that
use application-layer encryption on top of TLS — the pattern you hit
auditing mobile apps and SDKs that re-encrypt every payload over HTTPS.
Once configured, an encrypted API audits like a plain one: Repeater edits
plaintext, Scanner scans plaintext, Logger logs plaintext, and the wire
keeps carrying valid ciphertext.

## Mental model

A **scope rule** binds `(host pattern → pipeline → body location)`.
A **pipeline** is an ordered list of crypto steps. The **key store**
holds named key material referenced by step parameters. The body
**location** tells the extension where in the message the ciphertext
actually lives.

```
   client  ──ciphertext──►  Burp  ──plaintext──►  Burp tools
                            (decrypt)             (Repeater, Scanner,
                                                   Logger, History)

   Burp  ──plaintext──►  Burp  ──ciphertext──►  server
                         (re-encrypt)

   server  ──ciphertext──►  Burp  ──plaintext──►  Burp tools
                            (decrypt)

   Burp  ──plaintext──►  Burp  ──ciphertext──►  client
                         (re-encrypt)
```

Encryption walks pipeline steps top-to-bottom; decryption walks them
bottom-to-top — pipelines are inverses of themselves under valid input.

---

## Install

```bash
./gradlew shadowJar
```

The output is `build/libs/CryptoChef-1.0.0.jar`. In Burp:

```
Extensions → Installed → Add → Java → pick the .jar
```

You should see `[CryptoChef] loaded.` in the extension output and a new
**CryptoChef** tab at the top of Burp.

---

## Quick start

A worked example: a banking app that encrypts request and response
bodies with AES-256-CBC (random-prepended IV) and base64-wraps the result
on the wire.

**1. Add a key.** *CryptoChef → Key Store → Add key.*

| Field    | Value                              |
|----------|------------------------------------|
| Name     | `api-session-key`                  |
| Kind     | `raw`                              |
| Encoding | `hex`                              |
| Material | `000102…1e1f` (32 bytes hex)       |

**2. Build a pipeline.** *Pipelines → New → `mobile-banking`.* Add two
steps:

```
1. AES-256-CBC      key-ref = api-session-key, iv-mode = random
2. BASE64           variant = standard, padding = true
```

**3. Add a scope rule.** *Scope rules → Add rule…*

| Field        | Value                          |
|--------------|--------------------------------|
| Match kind   | `wildcard`                     |
| Host / URL   | `api.bank.example.com`         |
| Pipeline     | `mobile-banking`               |
| Body location| `whole`                        |

**4. Generate traffic.** Open Proxy History — Pretty / Raw / Hex now
show plaintext on every selected request. Repeater, Intruder, Scanner,
and Logger all see plaintext too. Edits in any of them are re-encrypted
on the way out.

If the ciphertext is wrapped in JSON like `{"data":"<base64>","iv":"…"}`,
set the rule's body location to `regex` with expression
`"data":"([^"]+)"` instead.

---

## Reference

### Supported schemes

| Scheme               | Notes                                                        |
|----------------------|--------------------------------------------------------------|
| AES-256/128-CBC      | PKCS#7. Fixed or random-prepended IV.                        |
| AES-256/128-GCM      | 12-byte nonce, random-prepended by default. Optional AAD.    |
| AES-256/128-ECB      | PKCS#7. Use only when the target forces it.                  |
| RSA-OAEP hybrid      | RSA-wrapped AES key + AES-GCM or AES-CBC body.               |
| JWE                  | RSA-OAEP-256+A256GCM, dir+A256GCM, ECDH-ES+A256GCM, …        |
| XOR                  | Repeat or truncate-to-key modes.                             |
| Base64               | Standard or URL-safe, optional padding.                      |
| Multilayer pipelines | Any ordered stack, e.g. `Base64 → AES-256-CBC → Base64`.     |

### Body locations

| Kind     | Use when                                                          |
|----------|-------------------------------------------------------------------|
| `whole`  | The entire HTTP body is the ciphertext.                           |
| `header` | The ciphertext lives in a single header value, e.g. `X-Payload`.  |
| `regex`  | The ciphertext is embedded in JSON, XML, or form data. Group 1 is the ciphertext (whole match if no group). `Pattern.DOTALL` is on. |

### Auto-mode handler chain

Auto decrypt/encrypt is unconditionally on for every Burp tool that
has its checkbox ticked at the top of the CryptoChef tab.

| Step                    | Handler                                                | Direction |
|-------------------------|--------------------------------------------------------|-----------|
| client → Burp           | `ProxyRequestHandler.handleRequestReceived`            | decrypt   |
| Burp → server (proxy)   | `ProxyRequestHandler.handleRequestToBeSent`            | encrypt   |
| Burp → server (other)   | `HttpHandler.handleHttpRequestToBeSent`                | encrypt   |
| server → Burp           | `HttpHandler.handleHttpResponseReceived`               | decrypt   |
| Burp → client           | `ProxyResponseHandler.handleResponseToBeSent`          | encrypt   |

The proxy split is what makes Burp's native Pretty / Raw tabs render
plaintext — the proxy intermediate state is captured into history before
the wire-side re-encryption runs.

The error tag `<X>` is the exception's class name (e.g. `BadPadding`,
`AEADBadTag`) — bounded by design so notes can't grow unboundedly in the
project file. Full exception detail goes to *Extensions → Output*.

### Decision matrix

| Condition                                                   | Action                      |
|-------------------------------------------------------------|-----------------------------|
| Empty body, or content already in plaintext shape           | pass-through + `cm:skipped` |
| Already marked (`cm:plaintext` in / `cm:ciphertext` out)    | pass-through (idempotent)   |
| Pipeline throws                                             | pass-through + `cm:error:…` |
| Otherwise                                                   | transform                   |

The extension never blocks traffic. On any failure the original bytes
reach their destination and the message is annotated.
---

## License

See [LICENSE](LICENSE).
