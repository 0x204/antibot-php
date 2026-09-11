<?php
// require_once, not include: a missing or unreadable antibot.php must be a
// fatal error, not a warning that lets the page render unprotected. __DIR__
// anchors the path to this file rather than the process working directory.
require_once __DIR__ . '/antibot.php';
?>
<h1>Hello World</h1>
