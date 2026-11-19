<?php

declare(strict_types=1);

// Copy to config.php, outside the web root if you can. Never commit the real secret.
//
// Create a secret once:   php -r "echo bin2hex(random_bytes(32)), PHP_EOL;"
// Then either set the environment variable FORMSCHUTZ_SECRET, or put the secret alone in a file
// outside the web root and point FORMSCHUTZ_SECRET_FILE at it.

$secret = getenv('FORMSCHUTZ_SECRET') ?: '';
if ($secret === '' && ($file = getenv('FORMSCHUTZ_SECRET_FILE')) !== false && is_file($file)) {
    $secret = trim((string) file_get_contents($file));
}

return [
    'secret' => $secret,
    // One folder per form or app, writable by PHP, not reachable from the web, used for nothing else.
    // Change it: a folder in the system temp dir may be cleared at any time.
    'storage' => sys_get_temp_dir() . '/formschutz-contact',
    'mail_to' => 'owner@example.com',
    'mail_from' => 'form@example.com',
];
