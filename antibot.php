<?php
declare(strict_types=1);

/**
 * antibot.php - a dependency-free proof-of-work gate for PHP.
 *
 * Include it at the very top of any page you want to protect, before that page
 * sends any output of its own:
 *
 *     require_once __DIR__ . '/antibot.php';
 *
 * Configuration (see README.md):
 *   ANTIBOT_SECRET      required. 32+ random bytes: `openssl rand -hex 32`.
 *   ANTIBOT_DIFFICULTY  optional. Leading hex zeros demanded of the digest.
 *
 * Supply either as an environment variable, or define() the constant before
 * including this file. There is no built-in default secret - the gate fails
 * closed rather than protect a site with a value an attacker can read here.
 */

if (!class_exists('AntiBot', false)) {

final class AntiBot
{
    /** Bump to invalidate every issued pass at once. */
    private const VERSION = '2';

    private const COOKIE     = 'ab';
    private const TRY_COOKIE = 'ab_try';

    /** Challenge rounds before we stop looping and explain ourselves. */
    private const MAX_TRIES = 3;

    /** Lifetime of an issued pass, in seconds. */
    private const TTL = 86400;

    /** Reissue silently once a pass has less than this much left. */
    private const RENEW_AFTER = 21600;

    /** How long a challenge stays solvable. */
    private const CHALLENGE_TTL = 300;

    private const DEFAULT_DIFFICULTY = 4;
    private const MAX_DIFFICULTY     = 8;

    private static bool $ran = false;

    private string $secret;
    private int $difficulty;
    private string $binding;

    public static function protect(): void
    {
        // Guards against a second require in the same request (a header.php
        // and a footer.php both pulling the gate in) re-running everything.
        if (self::$ran) {
            return;
        }
        self::$ran = true;

        (new self())->run();
    }

    private function __construct()
    {
        $this->secret     = $this->readSecret();
        $this->difficulty = $this->readDifficulty();
        $this->binding    = $this->clientBinding();
    }

    private function run(): void
    {
        if (($_SERVER['REQUEST_METHOD'] ?? 'GET') === 'POST'
            && ($_POST['__ab_op'] ?? '') === 'verify') {
            $this->handleVerify(); // exits
        }

        // $_COOKIE['ab'] is an array if a client sends `ab[]=x`, which would
        // make hash_equals() throw; is_string() keeps that a plain rejection.
        $token  = $_COOKIE[self::COOKIE] ?? null;
        $expiry = is_string($token) ? $this->validate($token) : null;

        if ($expiry !== null) {
            // Slide the expiry forward while the visitor is active, so a pass
            // never lapses mid-session and swallows a form submission.
            if ($expiry - time() < self::RENEW_AFTER) {
                $this->issue();
            }

            // Protected responses differ by cookie; without this a shared
            // cache may hand this body to a client that presented none.
            $this->header('Vary', 'Cookie');

            return; // hand control back to the page that included us
        }

        $this->challenge(); // exits
    }

    // -- configuration -----------------------------------------------------

    private function readSecret(): string
    {
        $secret = '';
        if (defined('ANTIBOT_SECRET')) {
            $secret = (string) constant('ANTIBOT_SECRET');
        } elseif (($env = getenv('ANTIBOT_SECRET')) !== false) {
            $secret = (string) $env;
        }
        $secret = trim($secret);

        // A secret that ships in the repository is not a secret: anyone can
        // forge a pass offline. Refuse to run rather than look protected.
        if ($secret === '' || strlen($secret) < 16) {
            $this->page(
                503,
                'AntiBot is not configured',
                'Set ANTIBOT_SECRET to at least 16 random characters '
                . '(openssl rand -hex 32) before serving this site.'
            );
        }

        return $secret;
    }

    private function readDifficulty(): int
    {
        $raw = defined('ANTIBOT_DIFFICULTY')
            ? constant('ANTIBOT_DIFFICULTY')
            : getenv('ANTIBOT_DIFFICULTY');

        $value = is_numeric($raw) ? (int) $raw : self::DEFAULT_DIFFICULTY;

        return max(1, min(self::MAX_DIFFICULTY, $value));
    }

    /**
     * A deliberately coarse client fingerprint.
     *
     * Binding a pass to the exact address and the exact User-Agent means a
     * browser auto-update, or a carrier handing out a new CGNAT address,
     * silently invalidates it and drops the visitor back into the challenge.
     * So we widen both: an IPv4 /24, an IPv6 /64, and a UA with every version
     * number stripped out.
     */
    private function clientBinding(): string
    {
        $ip = (string) ($_SERVER['REMOTE_ADDR'] ?? '');
        $ua = (string) ($_SERVER['HTTP_USER_AGENT'] ?? '');

        if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4) !== false) {
            $ip = implode('.', array_slice(explode('.', $ip), 0, 3)) . '.0/24';
        } elseif (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6) !== false) {
            $ip = bin2hex(substr((string) inet_pton($ip), 0, 8)) . '/64';
        } else {
            $ip = '';
        }

        $ua = (string) preg_replace('/[0-9]+/', '', $ua);

        return $ip . '|' . substr($ua, 0, 256);
    }

    // -- tokens ------------------------------------------------------------

    private function sign(string $purpose, string ...$parts): string
    {
        $payload = implode('|', array_merge(
            [self::VERSION, $purpose, $this->binding],
            $parts
        ));

        return hash_hmac('sha256', $payload, $this->secret);
    }

    /** @return int|null the expiry timestamp, or null when the pass is no good */
    private function validate(string $token): ?int
    {
        if (strlen($token) > 128 || substr_count($token, '.') !== 1) {
            return null;
        }

        [$exp, $mac] = explode('.', $token, 2);

        if (!ctype_digit($exp) || !ctype_xdigit($mac)) {
            return null;
        }

        // The expiry is inside the signed payload, so the server - not the
        // cookie jar - decides when a pass dies. Reject stale passes, and
        // ones minted with a lifetime we would never have issued.
        $expiry = (int) $exp;
        $now    = time();
        if ($expiry <= $now || $expiry > $now + self::TTL) {
            return null;
        }

        // Constant-time: a plain !== leaks the matching prefix through timing.
        return hash_equals($this->sign('pass', $exp), $mac) ? $expiry : null;
    }

    private function issue(): void
    {
        $expiry = time() + self::TTL;

        $this->setCookie(
            self::COOKIE,
            $expiry . '.' . $this->sign('pass', (string) $expiry),
            $expiry
        );
    }

    private function solved(string $nonce, string $counter): bool
    {
        $digest = hash('sha256', $nonce . '.' . $counter);

        return strncmp($digest, str_repeat('0', $this->difficulty), $this->difficulty) === 0;
    }

    // -- request handling --------------------------------------------------

    private function handleVerify(): void
    {
        $this->noStore();
        $this->header('Content-Type', 'application/json; charset=utf-8');

        $ts      = (string) ($_POST['ts']    ?? '');
        $nonce   = (string) ($_POST['nonce'] ?? '');
        $sig     = (string) ($_POST['sig']   ?? '');
        $counter = (string) ($_POST['n']     ?? '');

        $ok = ctype_digit($ts)
            && strlen($nonce) === 32 && ctype_xdigit($nonce)
            && strlen($sig) === 64 && ctype_xdigit($sig)
            && $counter !== '' && strlen($counter) <= 20 && ctype_digit($counter)
            && abs(time() - (int) $ts) <= self::CHALLENGE_TTL
            && hash_equals($this->sign('challenge', $ts, $nonce), $sig)
            && $this->solved($nonce, $counter);

        if ($ok) {
            $this->issue();
            $this->setCookie(self::TRY_COOKIE, '', time() - 3600);
        }

        echo json_encode(['ok' => $ok]);
        exit;
    }

    private function challenge(): void
    {
        $tries = (int) ($_COOKIE[self::TRY_COOKIE] ?? 0);

        // Without this the visitor bounces between page and challenge forever.
        if ($tries >= self::MAX_TRIES) {
            $this->page(
                403,
                'We could not verify your browser',
                'This check needs JavaScript and cookies enabled. Please turn '
                . 'both on and reload the page.'
            );
        }
        $this->setCookie(self::TRY_COOKIE, (string) ($tries + 1), time() + 600);

        $ts    = (string) time();
        $nonce = bin2hex(random_bytes(16));

        $this->page(
            503,
            'AntiBot Protection',
            'This process is automatic. Please wait a few seconds...',
            [
                'ts'         => $ts,
                'nonce'      => $nonce,
                'sig'        => $this->sign('challenge', $ts, $nonce),
                'difficulty' => $this->difficulty,
            ]
        );
    }

    // -- headers and cookies -----------------------------------------------

    private function header(string $name, string $value): void
    {
        if (!headers_sent()) {
            header($name . ': ' . $value);
        }
    }

    private function noStore(): void
    {
        // A cached challenge would pin one visitor's state onto everyone
        // behind the same proxy; a cached pass would be served to clients
        // holding no cookie at all.
        $this->header('Cache-Control', 'no-store, no-cache, must-revalidate, private');
        $this->header('Pragma', 'no-cache');
        $this->header('Vary', 'Cookie');
        $this->header('X-Robots-Tag', 'noindex, nofollow');
    }

    private function setCookie(string $name, string $value, int $expires): void
    {
        if (headers_sent()) {
            return;
        }

        // Set from PHP rather than document.cookie, which is what lets this
        // be HttpOnly: script on the page can no longer read the pass.
        setcookie($name, $value, [
            'expires'  => $expires,
            'path'     => '/',
            'secure'   => $this->isHttps(),
            'httponly' => true,
            'samesite' => 'Lax',
        ]);
    }

    private function isHttps(): bool
    {
        $https = (string) ($_SERVER['HTTPS'] ?? '');
        if ($https !== '' && strcasecmp($https, 'off') !== 0) {
            return true;
        }
        if (strcasecmp((string) ($_SERVER['HTTP_X_FORWARDED_PROTO'] ?? ''), 'https') === 0) {
            return true;
        }

        return (int) ($_SERVER['SERVER_PORT'] ?? 0) === 443;
    }

    // -- rendering ---------------------------------------------------------

    /**
     * @param array<string,mixed>|null $challenge null renders a terminal
     *                                            message with no retry loop
     */
    private function page(int $code, string $title, string $desc, ?array $challenge = null): void
    {
        $this->noStore();
        if (!headers_sent()) {
            http_response_code($code);
        }
        $this->header('Content-Type', 'text/html; charset=utf-8');
        if ($challenge !== null) {
            $this->header('Retry-After', '5');
        }

        // json_encode gives a correctly quoted and escaped JS literal, so the
        // page stays safe if any of these values ever becomes configurable.
        $payload = json_encode(
            $challenge,
            JSON_HEX_TAG | JSON_HEX_AMP | JSON_HEX_APOS | JSON_HEX_QUOT | JSON_UNESCAPED_SLASHES
        );
        $title = htmlspecialchars($title, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
        $desc  = htmlspecialchars($desc, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
        $spin  = $challenge !== null ? '' : ' hidden';
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <meta name="robots" content="noindex, nofollow">
    <title><?php echo $title; ?></title>
    <style>
        html, body { height: 100%; margin: 0; padding: 0; }
        body {
            min-height: 100vh;
            background: linear-gradient(to bottom, rgba(60,62,70,0.72) 0%, rgba(40,42,48,0.82) 100%);
            background-color: #2a2c30;
            color: #fff;
            /* System stack only. A webfont in <head> blocks the script below
               until it resolves, so a slow CDN would stall the whole gate. */
            font-family: 'Manrope', 'Segoe UI', system-ui, -apple-system, Arial, sans-serif;
            font-weight: 400;
            display: flex;
            flex-direction: column;
            justify-content: center;
            align-items: center;
            position: relative;
            overflow: hidden;
            -webkit-font-smoothing: antialiased;
            -moz-osx-font-smoothing: grayscale;
        }
        .centered {
            text-align: center;
            animation: fadeIn 1.2s cubic-bezier(.4,0,.2,1);
            max-width: 90vw;
            padding: 0 16px;
        }
        @keyframes fadeIn {
            from { opacity: 0; transform: translateY(40px); }
            to   { opacity: 1; transform: none; }
        }
        .title { font-size: 2.2em; font-weight: 700; margin-bottom: 16px; letter-spacing: 0.2px; }
        .desc {
            color: #bdbdbd;
            font-size: 1em;
            margin-bottom: 24px;
            letter-spacing: 0.05px;
            max-width: 34em;
            margin-left: auto;
            margin-right: auto;
        }
        .loader {
            width: 50px;
            aspect-ratio: 1;
            max-width: 100%;
            display: grid;
            border: 4px solid #0000;
            border-radius: 50%;
            border-right-color: #25b09b;
            animation: l15 1s infinite linear;
            margin: 0 auto 22px auto;
        }
        .loader::before, .loader::after {
            content: "";
            grid-area: 1/1;
            margin: 2px;
            border: inherit;
            border-radius: 50%;
            animation: l15 2s infinite;
        }
        .loader::after { margin: 8px; animation-duration: 3s; }
        @keyframes l15 { 100% { transform: rotate(1turn) } }
        .powered {
            position: fixed;
            left: 50%;
            bottom: 24px;
            transform: translateX(-50%);
            z-index: 10;
            display: flex;
            align-items: center;
            justify-content: center;
            gap: 7px;
            font-size: 1.05em;
            opacity: 0.65;
            transition: opacity 0.2s;
            text-decoration: none;
            color: #fff;
            border-radius: 8px;
            padding: 0.3em 1em;
        }
        .powered:hover { opacity: 1; }
        .powered svg {
            width: 1.15em;
            height: 1.15em;
            vertical-align: middle;
            fill: #fff;
            opacity: 0.85;
            transition: fill 0.2s;
        }
        .powered:hover svg { fill: #25b09b; }
        @media (max-width: 600px) {
            .title { font-size: 1.3em; }
            .powered { font-size: 0.97em; padding: 0.3em 0.7em; }
        }
        @media (prefers-reduced-motion: reduce) {
            .centered { animation: none; }
            .loader, .loader::before, .loader::after { animation-duration: 4s; }
        }
    </style>
</head>
<body>
    <div class="centered">
        <div class="title"><?php echo $title; ?></div>
        <div class="loader"<?php echo $spin; ?>></div>
        <div class="desc" id="ab-desc"><?php echo $desc; ?></div>
        <noscript>
            <div class="desc">
                This check requires JavaScript. Please enable it and reload the page.
            </div>
        </noscript>
    </div>
    <a class="powered" href="https://github.com/0x204" target="_blank" rel="noopener noreferrer">
        <span>Powered by</span>
        <svg viewBox="0 0 24 24" aria-hidden="true"><path d="M12 0C5.37 0 0 5.37 0 12c0 5.3 3.438 9.8 8.207 11.387.6.113.793-.262.793-.583 0-.288-.01-1.05-.016-2.06-3.338.726-4.042-1.61-4.042-1.61-.546-1.387-1.333-1.756-1.333-1.756-1.09-.745.083-.73.083-.73 1.205.085 1.84 1.237 1.84 1.237 1.07 1.834 2.807 1.304 3.492.997.108-.775.418-1.305.762-1.606-2.665-.304-5.466-1.332-5.466-5.93 0-1.31.468-2.38 1.236-3.22-.124-.303-.535-1.523.117-3.176 0 0 1.008-.322 3.3 1.23a11.5 11.5 0 0 1 3.003-.404c1.02.005 2.047.138 3.003.404 2.29-1.552 3.297-1.23 3.297-1.23.653 1.653.242 2.873.12 3.176.77.84 1.235 1.91 1.235 3.22 0 4.61-2.803 5.624-5.475 5.922.43.37.823 1.102.823 2.222 0 1.606-.015 2.898-.015 3.293 0 .324.192.699.8.58C20.565 21.796 24 17.297 24 12c0-6.63-5.37-12-12-12z"/></svg>
        <span>0x204</span>
    </a>
<script>
(function () {
    "use strict";

    var C = <?php echo $payload; ?>;
    if (!C) { return; }

    var desc = document.getElementById("ab-desc");
    function say(text) { if (desc) { desc.textContent = text; } }

    if (!navigator.cookieEnabled) {
        say("Cookies are disabled. Please enable them and reload the page.");
        return;
    }

    var K = [
        0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
        0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
        0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
        0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
        0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
        0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
        0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
        0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2
    ];
    var W = new Int32Array(64);

    function ror(x, n) { return (x >>> n) | (x << (32 - n)); }

    // SHA-256 over an ASCII string. The gate only ever hashes hex + digits.
    function sha256hex(msg) {
        var len = msg.length,
            blocks = ((len + 8) >> 6) + 1,
            words = new Int32Array(blocks * 16),
            i, j, t, s0, s1, ch, maj, t1, t2, a, b, c, d, e, f, g, h;

        for (i = 0; i < len; i++) {
            words[i >> 2] |= (msg.charCodeAt(i) & 0xff) << (24 - (i % 4) * 8);
        }
        words[len >> 2] |= 0x80 << (24 - (len % 4) * 8);
        words[blocks * 16 - 1] = len * 8;

        var H0 = 0x6a09e667, H1 = 0xbb67ae85, H2 = 0x3c6ef372, H3 = 0xa54ff53a,
            H4 = 0x510e527f, H5 = 0x9b05688c, H6 = 0x1f83d9ab, H7 = 0x5be0cd19;

        for (j = 0; j < blocks * 16; j += 16) {
            a = H0; b = H1; c = H2; d = H3; e = H4; f = H5; g = H6; h = H7;

            for (t = 0; t < 64; t++) {
                if (t < 16) {
                    W[t] = words[j + t];
                } else {
                    s0 = ror(W[t - 15], 7) ^ ror(W[t - 15], 18) ^ (W[t - 15] >>> 3);
                    s1 = ror(W[t - 2], 17) ^ ror(W[t - 2], 19) ^ (W[t - 2] >>> 10);
                    W[t] = (W[t - 16] + s0 + W[t - 7] + s1) | 0;
                }
                s1 = ror(e, 6) ^ ror(e, 11) ^ ror(e, 25);
                ch = (e & f) ^ (~e & g);
                t1 = (h + s1 + ch + K[t] + W[t]) | 0;
                s0 = ror(a, 2) ^ ror(a, 13) ^ ror(a, 22);
                maj = (a & b) ^ (a & c) ^ (b & c);
                t2 = (s0 + maj) | 0;
                h = g; g = f; f = e; e = (d + t1) | 0;
                d = c; c = b; b = a; a = (t1 + t2) | 0;
            }
            H0 = (H0 + a) | 0; H1 = (H1 + b) | 0; H2 = (H2 + c) | 0; H3 = (H3 + d) | 0;
            H4 = (H4 + e) | 0; H5 = (H5 + f) | 0; H6 = (H6 + g) | 0; H7 = (H7 + h) | 0;
        }

        var out = "", all = [H0, H1, H2, H3, H4, H5, H6, H7];
        for (i = 0; i < 8; i++) {
            out += ("0000000" + (all[i] >>> 0).toString(16)).slice(-8);
        }
        return out;
    }

    var target = new Array(C.difficulty + 1).join("0"),
        prefix = C.nonce + ".",
        started = Date.now(),
        n = 0;

    // Solve in slices so the spinner keeps animating and the tab stays alive.
    function work() {
        var stop = n + 4000;
        for (; n < stop; n++) {
            if (sha256hex(prefix + n).slice(0, C.difficulty) === target) {
                submit(n);
                return;
            }
        }
        if (Date.now() - started > 60000) {
            say("Verification is taking longer than expected. Please reload the page.");
            return;
        }
        setTimeout(work, 0);
    }

    function submit(answer) {
        var body = "__ab_op=verify"
            + "&ts=" + encodeURIComponent(C.ts)
            + "&nonce=" + encodeURIComponent(C.nonce)
            + "&sig=" + encodeURIComponent(C.sig)
            + "&n=" + encodeURIComponent(answer);

        fetch(location.href, {
            method: "POST",
            credentials: "same-origin",
            cache: "no-store",
            headers: { "Content-Type": "application/x-www-form-urlencoded" },
            body: body
        }).then(function (r) {
            return r.json();
        }).then(function (data) {
            if (data && data.ok) {
                // Reload the URL actually requested - no hardcoded
                // destination, and replace() keeps this out of history.
                // Always a GET, so no resubmission prompt.
                location.replace(location.href);
            } else {
                say("Verification failed. Please reload the page to try again.");
            }
        })["catch"](function () {
            say("Verification could not be completed. Please reload the page.");
        });
    }

    work();
})();
</script>
</body>
</html>
<?php
        exit;
    }
}

}

AntiBot::protect();
