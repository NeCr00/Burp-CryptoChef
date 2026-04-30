# CryptoChef — Burp Suite extension for application-layer crypto

CryptoChef is a Burp Suite extension that transparently decrypts and
re-encrypts HTTP request and response bodies that use application-layer
encryption on top of TLS — the pattern you routinely hit when pen-testing
mobile apps that "helpfully" re-encrypt everything they send over HTTPS.

With CryptoChef, the experience of auditing an encrypted mobile API feels
the same as a plain one:

- Proxy history shows **plaintext** bodies.
- Repeater edits on plaintext; the wire carries correct ciphertext.
- Intruder, Scanner and Logger all see plaintext.
- The **Decrypted** tab appears next to Burp's Raw/Pretty/Hex tabs.
- A right-click **CryptoChef → …** submenu lets you transform
  selections or whole bodies on demand.

## Supported schemes

| Scheme                                  | Notes |
|-----------------------------------------|-------|
| AES-256-CBC (PKCS#7)                    | fixed or random-prepended IV |
| AES-128-CBC (PKCS#7)                    | same |
| AES-256-GCM                             | random-prepended nonce, optional AAD |
| AES-256-ECB (PKCS#7)                    | not safe, but common in the wild |
| RSA-OAEP hybrid                         | RSA-wrapped AES key + AES-GCM or AES-CBC body |
| JWE                                     | RSA-OAEP-256+A256GCM, dir+A256GCM, ECDH-ES+A256GCM, plus anything Nimbus supports |
| XOR                                     | repeat or truncate modes |
| Base64                                  | standard / URL-safe, optional padding |
| Multilayer pipelines                    | user-defined ordered stacks, e.g. `Base64 → AES-256-CBC → Base64` |

## Installation

1. Build the jar:

   ```
   ./gradlew shadowJar
   ```

   The output is `build/libs/CryptoChef-1.0.0.jar`.

2. In Burp Suite Professional: **Extensions → Installed → Add → Java**, pick
   the jar. You should see *"CryptoChef loaded."* in the extension
   output tab, and a new **CryptoChef** tab at the top of Burp.

Burp must be running on Java 17 or newer — the version bundled with Burp
Professional 2024.x is fine.

## Configuration walkthrough

### 1. Add a key

Open the **CryptoChef** tab → **Key Store** sub-tab → **Add key**:

- *Name:* `api-session-key`
- *Kind:* `raw`
- *Encoding:* `hex`
- *Material:* `000102…1e1f` (32 bytes hex = 256-bit key)

> (screenshot placeholder — key store UI)

### 2. Build a pipeline

Switch to the **Pipelines** sub-tab → **New** → name it `mobile-banking`.

Click **Add step** and fill in:

| field             | value          |
|-------------------|----------------|
| type              | `BASE64`       |
| variant           | `standard`     |
| padding           | `true`         |

Add a second step:

| field             | value              |
|-------------------|--------------------|
| type              | `AES-256-CBC`      |
| key-ref           | `api-session-key`  |
| iv-mode           | `random`           |

The pipeline runs **top-to-bottom on encrypt**, **bottom-to-top on decrypt**
— so in the example above, decryption is: Base64-decode, then AES-CBC-decrypt.

### 3. Bind the pipeline to a scope

Switch to the **Scope rules** tab → click **Add rule…** and fill in the
dialog (each rule carries its own body location now — there is no separate
global default):

- *Enabled:* ✓
- *Match kind:* `wildcard`
- *Host / URL:* `api.bank.example.com`
- *Pipeline:* `mobile-banking`
- *Body location:* `regex`
- *Expression:* `"data":"([^"]+)"` (or pick `whole` if the entire body is
  the ciphertext, or `header` for an `X-Payload`-style header)

Click **Apply**.

### 4. Test against real traffic

Auto decrypt/encrypt is unconditionally on for every supported tool — there
is no master switch to flip. Just generate traffic:

- Open **Proxy → HTTP history**, pick a request to `api.bank.example.com`.
- You'll see a new **Decrypted** tab alongside Raw / Pretty / Hex, and the
  native Pretty / Raw tabs themselves now also render plaintext.
- Right-click the body for the **CryptoChef → Decrypt body** context-menu
  entry.

### 5. How auto-mode works

The handler chain is arranged so that Burp's NATIVE Pretty / Raw / Hex
tabs show plaintext — the extension's "Decrypted" tab is just an extra
view for explicit auditing.

For proxied traffic from a real client app:

- **Client → Burp** — `ProxyRequestHandler.handleRequestReceived` decrypts
  the ciphertext at the configured location. Everything Burp stores from
  this point on (Proxy History, Logger, Scanner queue, "Send to Repeater"
  snapshots) captures the PLAINTEXT version.
- **Burp → server** — `ProxyRequestHandler.handleRequestToBeSent`
  re-encrypts. The wire gets correctly formatted ciphertext. The
  `HttpHandler` hook deliberately does NOT touch proxy requests, because
  its modifications land after Proxy History has been snapshotted and
  would leak ciphertext into the UI.
- **Server → Burp** — `HttpHandler.handleHttpResponseReceived` decrypts.
  History and all tools see plaintext.
- **Burp → client** — `ProxyResponseHandler.handleResponseToBeSent`
  re-encrypts so the client app keeps receiving valid ciphertext as if
  Burp weren't there.

For non-proxy tools (Repeater, Intruder, Scanner, Logger):

- You type plaintext and click Send. `HttpHandler.handleHttpRequestToBeSent`
  encrypts before the wire. Your editor pane still shows the plaintext you
  typed; the server receives ciphertext.
- The response arrives, `HttpHandler.handleHttpResponseReceived` decrypts,
  and the response pane shows plaintext.

**One quirk** — Intruder's results table displays each attack row's
request in its post-HttpHandler form, which is the ciphertext wire
version. Payload positions you define in the plaintext template still work
(the payload is substituted before encryption), but the results table
column is ciphertext. Click an Intruder row → Request tab shows
plaintext, or open the item in Repeater to view + re-send plaintext.

**Prerequisites** — auto-mode is a no-op until you have:

1. At least one enabled **Scope rule** (Scope rules tab).
2. At least one **Pipeline** (Pipelines tab) referenced by that rule.

Until you configure those two, all traffic passes through unchanged.

**Per-tool / per-direction toggles** — the bar at the top of the CryptoChef
tab lets you exclude individual Burp tools (Proxy / Repeater / Intruder /
Logger / Scanner) or directions (Requests / Responses) from auto-mode. The
common reason to flip one off is to spare Scanner from re-encrypting on
every audit hit when you're stress-testing throughput.

#### Annotation scheme

Every in-scope message gets exactly one of these notes; check Proxy
History's **Notes** column to see what the extension decided:

| Note            | Meaning                                                                            | Highlight |
|-----------------|------------------------------------------------------------------------------------|-----------|
| `cm:plaintext`  | Body was decrypted successfully — what you see is the real plaintext.              | Cyan      |
| `cm:ciphertext` | Body was encrypted successfully on the way out (or already ciphertext on receipt). | Green     |
| `cm:skipped`    | Body was not in a shape that matched the pipeline (empty, plaintext error, etc.).  | —         |
| `cm:error:…`    | Transformation threw. The original bytes were forwarded untouched.                 | Red       |

**Out-of-scope traffic** is byte-identical before and after and carries no
annotations.

#### Decision matrix (per in-scope message)

| Condition                                                         | Action                         |
|-------------------------------------------------------------------|--------------------------------|
| Location missing, empty, or content doesn't match pipeline shape  | Pass through + `cm:skipped`    |
| Already marked (`cm:plaintext` inbound / `cm:ciphertext` outbound)| Pass through (idempotent)      |
| Pipeline throws                                                    | Pass through + `cm:error:…`    |
| Otherwise                                                          | Transform                      |

The extension never blocks traffic: on any failure the original bytes
reach their destination.

## Worked example — Base64(AES-256-CBC(body))

```
Outgoing (browser → wire):

  User edits JSON in the Decrypted tab of Repeater →
    CryptoChef splices the new plaintext into the request →
    pipeline encrypts (AES-CBC → Base64) →
    request hits server with ciphertext body.

Incoming (wire → browser):

  Server sends back ciphertext body →
    pipeline decrypts (Base64 → AES-CBC) →
    Proxy history stores plaintext →
    tester sees JSON directly in every Burp tool.
```

## Troubleshooting

| Symptom                                                                                     | Fix |
|---------------------------------------------------------------------------------------------|-----|
| "Decrypted" tab never appears.                                                              | Your scope rule probably doesn't match, or the pipeline fails. The tab only shows up if decryption succeeds end-to-end. Use **Test pipeline** to iterate. |
| "AES-CBC: bad padding at step 2 of pipeline" in the banner.                                 | Wrong key, wrong IV, or the ciphertext isn't actually AES-CBC. Try flipping `iv-mode` between `fixed` and `random`. |
| Wire traffic looks unencrypted.                                                             | Check that the scope rule is enabled for the target host, and that **Tools: Proxy** + **Direction: Requests** are both ticked at the top of the CryptoChef tab. |
| Proxy History / Logger / Repeater / Scanner still show ciphertext.                          | You almost certainly have no Scope rule or no Pipeline configured. Check Extensions → Output for `[CryptoChef] PRH.reqReceived … → skip (no scope match)` — that means the rule pattern does not match your host/URL. |
| Body is wrapped in a JSON envelope (e.g. `{"ct":"…","iv":"…"}`).                            | The `whole`-body location sees valid JSON and classifies it as plaintext, so decryption is skipped. Open the matching scope rule and switch its **Body location** to `regex` with group 1 around the inner ciphertext, or to `header` if the ciphertext lives in a header. |
| Repeater edits aren't re-encrypting.                                                        | Make sure the **Decrypted** tab has focus when you click Send — Burp uses the currently-selected editor's bytes. |
| `No RSA private key configured` on responses.                                               | You only need the public key for encryption; decryption needs the private key. Add a `pem-private` key to the Key Store and reference it in the step. |
| Same pipeline + key + traffic decrypts cleanly on macOS Burp but fails on Linux/Kali Burp with "bad padding", "auth tag mismatch", or "ciphertext too short". | Some Burp-on-Linux installs (Kali running Burp Pro under the system OpenJDK is the common case) hand the extension a body byte-array with a trailing `0x0A` that's absent on macOS. Pipelines whose first decrypt step is a raw binary cipher (AES-CBC/GCM/ECB, XOR, RSA-OAEP) then see a non-block-aligned input and fail. CryptoChef trims trailing CR/LF at extraction time when the body looks textual (printable ASCII + whitespace), which covers base64/hex/JWE blobs without touching genuine binary payloads. If your wire body is raw binary (no base64 wrapper) and you still see this, wrap it: add a `BASE64` step on top of the cipher step — the base64 layer's internal whitespace stripping makes the pipeline platform-insensitive. |

## Known limitations and next steps

- **ECDH-ES JWE encryption** relies on Nimbus's default ephemeral-key
  generation. Custom epk injection / agreement-party-u/v overrides are not
  exposed in the UI — add them if you need to interop with an app that
  expects specific agreement parameters.
- **Protobuf-aware bodies** are not supported. If the ciphertext is wrapped
  in a protobuf message, use the regex/JSONPath selector to extract the raw
  bytes-field or add a custom step.
- **White-box / native hook integration** (Frida, Objection) is out of
  scope — but the Config JSON is trivially machine-readable, so feeding
  dynamically-recovered keys into the key store is one Frida-JS `fetch`
  away.
- **Streaming bodies / chunked transfer** decryption happens after Burp
  has assembled the full body, as with all Montoya HTTP handlers. Not a
  problem for the mobile apps this was built for.
- **Content-Length vs Transfer-Encoding**: rely on Montoya's `withBody()`
  to recompute — do not hand-edit the header.
- **Per-session keys**: if the app negotiates a key per session (e.g. via
  ECDH over the first request), the key store currently requires you to
  plug in the negotiated key manually. A `DerivedKey` step hooking a Frida
  script is the obvious follow-up.

Tested against Burp Suite Professional 2024.x on Java 17/21.
