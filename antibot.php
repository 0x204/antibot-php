<?php
$antibot_secret = 'mykey228';

function get_ab_token($ip, $ua, $secret) {
    return hash_hmac('sha256', $ip . '|' . $ua, $secret);
}

$ip = $_SERVER['REMOTE_ADDR'] ?? '';
$ua = $_SERVER['HTTP_USER_AGENT'] ?? '';
$expected_token = get_ab_token($ip, $ua, $antibot_secret);

$cookie_name = 'ab';
$cookie_token = $_COOKIE[$cookie_name] ?? '';

if ($cookie_token !== $expected_token) {
    ?>
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>AntiBot Protection</title>
        <link href="https://fonts.googleapis.com/css2?family=Manrope:wght@400;600;700&display=swap" rel="stylesheet">
        <style>
            html, body {
                height: 100%;
                margin: 0;
                padding: 0;
            }
            body {
                min-height: 100vh;
                background: linear-gradient(to bottom, rgba(60,62,70,0.72) 0%, rgba(40,42,48,0.82) 100%);
                color: #fff;
                font-family: 'Manrope', 'Segoe UI', Arial, sans-serif;
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
            }
            @keyframes fadeIn {
                from { opacity: 0; transform: translateY(40px); }
                to   { opacity: 1; transform: none; }
            }
            .title {
                font-size: 2.2em;
                font-weight: 700;
                margin-bottom: 16px;
                letter-spacing: 0.2px;
                font-family: 'Manrope', 'Segoe UI', Arial, sans-serif;
            }
            .desc {
                color: #bdbdbd;
                font-size: 1em;
                margin-bottom: 24px;
                font-weight: 400;
                letter-spacing: 0.05px;
                font-family: 'Manrope', 'Segoe UI', Arial, sans-serif;
            }
            /* Loader styles */
            .loader {
                width: 50px;
                aspect-ratio: 1;
                display: grid;
                border: 4px solid #0000;
                border-radius: 50%;
                border-right-color: #25b09b;
                animation: l15 1s infinite linear;
                margin: 0 auto 22px auto;
            }
            .loader::before,
            .loader::after {
                content: "";
                grid-area: 1/1;
                margin: 2px;
                border: inherit;
                border-radius: 50%;
                animation: l15 2s infinite;
            }
            .loader::after {
                margin: 8px;
                animation-duration: 3s;
            }
            @keyframes l15{
                100%{transform: rotate(1turn)}
            }
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
                font-family: 'Manrope', 'Segoe UI', Arial, sans-serif;
                background: none;
                box-shadow: none;
                border-radius: 8px;
                padding: 0.3em 1em;
            }
            .powered:hover {
                opacity: 1;
            }
            .powered svg {
                width: 1.15em;
                height: 1.15em;
                vertical-align: middle;
                fill: #fff;
                opacity: 0.85;
                transition: fill 0.2s;
            }
            .powered:hover svg {
                fill: #25b09b;
            }
            @media (max-width: 600px) {
                .title { font-size: 1.3em; }
                .powered { font-size: 0.97em; padding: 0.3em 0.7em; }
            }
        </style>
    </head>
    <body>
        <div class="centered">
            <div class="title">AntiBot Protection</div>
            <div class="desc">This process is automatic. Please wait a few seconds...</div>
            <div class="loader"></div>
        </div>
        <a class="powered" href="https://github.com/0x204" target="_blank" rel="noopener noreferrer">
            <span>Powered by</span>
            <svg viewBox="0 0 24 24" aria-hidden="true"><path d="M12 0C5.37 0 0 5.37 0 12c0 5.3 3.438 9.8 8.207 11.387.6.113.793-.262.793-.583 0-.288-.01-1.05-.016-2.06-3.338.726-4.042-1.61-4.042-1.61-.546-1.387-1.333-1.756-1.333-1.756-1.09-.745.083-.73.083-.73 1.205.085 1.84 1.237 1.84 1.237 1.07 1.834 2.807 1.304 3.492.997.108-.775.418-1.305.762-1.606-2.665-.304-5.466-1.332-5.466-5.93 0-1.31.468-2.38 1.236-3.22-.124-.303-.535-1.523.117-3.176 0 0 1.008-.322 3.3 1.23a11.5 11.5 0 0 1 3.003-.404c1.02.005 2.047.138 3.003.404 2.29-1.552 3.297-1.23 3.297-1.23.653 1.653.242 2.873.12 3.176.77.84 1.235 1.91 1.235 3.22 0 4.61-2.803 5.624-5.475 5.922.43.37.823 1.102.823 2.222 0 1.606-.015 2.898-.015 3.293 0 .324.192.699.8.58C20.565 21.796 24 17.297 24 12c0-6.63-5.37-12-12-12z"/></svg>
            <span>0x204</span>
        </a>
        <script>
            function setCookie(name, value, seconds) {
                var d = new Date();
                d.setTime(d.getTime() + (seconds * 1000));
                document.cookie = name + '=' + value + '; expires=' + d.toUTCString() + '; path=/';
            }
            setTimeout(function() {
                setCookie('<?php echo $cookie_name; ?>', '<?php echo $expected_token; ?>', 86400);
                window.location.href = 'example.php';
            }, 5000);
</script>
    </body>
    </html>
		<?php
		exit;
}
?>
