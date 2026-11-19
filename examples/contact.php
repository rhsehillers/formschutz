<?php

declare(strict_types=1);

// Plain contact form with Post-Redirect-Get. Run: php -S localhost:8000 -t examples

require __DIR__ . '/../src/autoload.php';

use Formschutz\Config;
use Formschutz\Fields;
use Formschutz\FileRateLimiter;
use Formschutz\Guard;
use Formschutz\Input;
use Formschutz\Reason;
use Formschutz\Verdict;

$settings = require __DIR__ . '/config.php'; // copy of config.example.php
$config = new Config($settings['secret']); // add nightHours: [0, 5] for an optional night flag
$guard = new Guard($config, new FileRateLimiter($settings['storage'], $config));
$fields = new Fields($config);

$h = static fn (string $s): string => htmlspecialchars($s, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
// a POST value as string; an array (field[]=x) becomes '' instead of "Array"
$post = static fn (string $key): string => is_string($_POST[$key] ?? null) ? $_POST[$key] : '';
$errors = [];

if (($_SERVER['REQUEST_METHOD'] ?? 'GET') === 'POST') {
    $name = Input::singleLine($post('name'));
    $email = Input::singleLine($post('email'));
    $message = Input::stripControl($post('message'));

    if ($name === false || $name === '') {
        $errors['name'] = 'Bitte geben Sie Ihren Namen an.';
    }
    if ($email === false || filter_var($email, FILTER_VALIDATE_EMAIL) === false) {
        $errors['email'] = 'Bitte geben Sie eine gültige E-Mail-Adresse an.';
    }
    if (trim($message) === '') {
        $errors['message'] = 'Bitte schreiben Sie eine Nachricht.';
    }

    if ($errors === []) {
        try {
            // behind a proxy, take the IP as described in the README instead of REMOTE_ADDR
            $verdict = $guard->inspect($_POST, $_SERVER['REMOTE_ADDR'] ?? '');
        } catch (\RuntimeException $e) {
            // the limiter store failed: do not lose a real message; send it flagged
            error_log('formschutz: ' . $e->getMessage());
            $verdict = Verdict::flag(Reason::LimiterError);
        }

        $sent = true;
        if (!$verdict->isDrop()) { // a Drop shows the same success page, but sends nothing
            $subject = 'Kontaktformular: ' . $name;
            if ($verdict->isFlag()) {
                // probably a human, but unusual: sent, and marked for a second look
                $reasons = implode(', ', array_map(static fn (Reason $r): string => $r->value, $verdict->reasons));
                $subject = 'PRÜFEN (' . $reasons . ') ' . $subject;
            }
            $sent = mail(
                $settings['mail_to'],
                mb_encode_mimeheader($subject, 'UTF-8', 'B'),
                $message,
                ['From' => $settings['mail_from'], 'Reply-To' => $email, 'Content-Type' => 'text/plain; charset=UTF-8'],
            );
            if (!$sent) {
                error_log('formschutz example: mail() failed');
                $errors['form'] = 'Die Nachricht konnte gerade nicht gesendet werden. Bitte versuchen Sie es später noch einmal.';
            }
        }
        if ($sent) {
            header('Location: ?sent=1', true, 303);
            exit;
        }
    }
}
?>
<!DOCTYPE html>
<html lang="de">
<head>
<meta charset="utf-8">
<title>Kontakt</title>
</head>
<body>
<?php if (isset($_GET['sent'])): ?>
<p>Danke, Ihre Nachricht ist angekommen.</p>
<?php else: ?>
<form method="post">
    <?php foreach ($errors as $error): ?><p><?= $h($error) ?></p><?php endforeach; ?>
    <p><label>Name <input name="name" value="<?= $h($post('name')) ?>"></label></p>
    <p><label>E-Mail <input name="email" type="email" value="<?= $h($post('email')) ?>"></label></p>
    <p><label>Nachricht <textarea name="message"><?= $h($post('message')) ?></textarea></label></p>
    <?= $fields->html() ?>
    <p><button>Senden</button></p>
</form>
<?php endif; ?>
</body>
</html>
