# antibot-php

A small, dependency-free proof-of-work gate for PHP. Drop one `require_once` at
the top of a page and unverified clients get an interstitial that their browser
has to solve before the real page is served.

<img width="1991" height="1388" alt="image" src="https://github.com/user-attachments/assets/3b66e59e-44c3-4d28-9d02-ea4416c06a16" />

## Setup

The gate needs a secret, and it has no default — it fails closed and serves a
503 until you give it one.

```sh
openssl rand -hex 32          # generate a secret
export ANTIBOT_SECRET=<the value>
```

Set it however your stack passes environment variables (`SetEnv` in Apache,
`fastcgi_param` in nginx, an `.env` loader, a systemd unit). Alternatively,
define the constant before including the gate:

```php
define('ANTIBOT_SECRET', getenv('ANTIBOT_SECRET'));
require_once __DIR__ . '/antibot.php';
```

Keep the secret out of version control. Anyone who has it can mint a valid pass
offline without ever loading the challenge.

## Usage

```php
<?php
require_once __DIR__ . '/antibot.php';
?>
<h1>Hello World</h1>
```

It must come before the page sends any output, because the gate sets cookies
and status codes. Include it once per request; a second `require_once` is a
no-op.

## Configuration

| Variable | Default | Meaning |
| --- | --- | --- |
| `ANTIBOT_SECRET` | *(none — required)* | HMAC key. Minimum 16 characters; 32+ random bytes recommended. |
| `ANTIBOT_DIFFICULTY` | `4` | Leading hex zeros required of the proof-of-work digest. Each extra zero multiplies the client's work by 16. |

Difficulty `4` is roughly 65k SHA-256 hashes — a fraction of a second in a
browser. Raise it if you are under load; `6` and above is noticeable on phones.

## How it works

1. An unverified request gets a `503` carrying a random nonce, a timestamp and
   an HMAC over both.
2. The browser searches for a counter `n` where
   `sha256(nonce + "." + n)` starts with the required number of zeros, then
   POSTs the answer back.
3. The server re-checks the HMAC, the freshness window and the digest, and on
   success sets an `HttpOnly`, `SameSite=Lax` pass cookie itself.
4. The page reloads at the URL originally requested. The pass lasts 24 hours
   and renews silently while the visitor is active.

The pass is bound to a coarse fingerprint — an IPv4 `/24` or IPv6 `/64`, plus a
User-Agent with version numbers stripped — so a browser update or a new CGNAT
address does not throw the visitor back into the challenge.

## What this does and does not stop

It stops clients that do not run JavaScript: scrapers built on plain HTTP
libraries, naive crawlers, and drive-by scanners. The answer is not present in
the page, so harvesting it with a regex does not work.

It does **not** stop a determined attacker. Anyone willing to reimplement the
proof-of-work — it is fifteen lines of SHA-256 — can pass it; the difficulty
setting only decides how much CPU that costs them per pass. It is also not a
CAPTCHA, not rate limiting, and no defence against a headless browser. Treat it
as a cheap filter for background noise, not as an access control.

## Limitations

- A visitor whose pass has expired and who then submits a form loses the POST
  body; the gate can only redirect back with a GET. Sliding renewal makes this
  rare, but it can happen.
- Clients with cookies or JavaScript disabled cannot pass, and after three
  attempts get a `403` explaining why instead of looping.
- The gate reads `REMOTE_ADDR` directly. Behind a reverse proxy that is the
  proxy's address, so every visitor shares one binding — configure the proxy to
  set `REMOTE_ADDR` correctly (`mod_remoteip`, `real_ip_module`) if that
  matters to you.

## Requirements

PHP 7.4 or newer. No extensions beyond the defaults, no Composer packages.
