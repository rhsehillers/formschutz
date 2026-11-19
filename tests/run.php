<?php

declare(strict_types=1);

// Plain PHP tests, no framework. Run: php tests/run.php  (last line is "OK" on success)

require __DIR__ . '/../src/autoload.php';

use Formschutz\Config;
use Formschutz\Fields;
use Formschutz\FileRateLimiter;
use Formschutz\Guard;
use Formschutz\Input;
use Formschutz\Reason;
use Formschutz\Seal;
use Formschutz\SealStatus;

$failures = [];
$count = 0;
function check(bool $condition, string $name): void
{
    global $failures, $count;
    $count++;
    if (!$condition) {
        $failures[] = $name;
    }
}

function removeDir(string $dir): void
{
    foreach (glob($dir . '/*') ?: [] as $item) {
        is_dir($item) ? removeDir($item) : unlink($item);
    }
    @rmdir($dir);
}

function throws(callable $fn): bool
{
    try {
        $fn();
    } catch (\Throwable) {
        return true;
    }
    return false;
}

$secretA = str_repeat('a', 32);
$secretB = str_repeat('b', 32);
$now = 1_800_000_000; // a fixed point in time, 2027-01-15 08:00 UTC
$dir = sys_get_temp_dir() . '/formschutz-test-' . bin2hex(random_bytes(6));

try {
    $config = new Config($secretA);
    $seal = new Seal($config);

    // --- Config
    check(throws(fn () => new Config('short')), 'secret under 32 bytes is rejected');
    check(throws(fn () => new Config($secretA, 10, 5)), 'max below min is rejected');
    check(throws(fn () => new Config($secretA, nightHours: [25, 3])), 'bad night hours are rejected');
    check(throws(fn () => new Config($secretA, nightHours: [1, 2, 3])), 'night hours with three values are rejected');
    check(throws(fn () => new Config($secretA, timezone: 'Nowhere/Land')), 'unknown timezone is rejected');
    check(throws(fn () => new Config($secretA, sealField: 'a b')), 'invalid field name is rejected');
    check(throws(fn () => new Config($secretA, sealField: 'same', emptyField: 'same')), 'equal field names are rejected');
    check(throws(fn () => new FileRateLimiter($dir, $config, 0)), 'limit below 1 is rejected');
    check(property_exists($config, 'secret') && (new ReflectionProperty($config, 'secret'))->isPrivate(), 'secret is private');

    // --- Seal
    $made = $seal->create($now - 10);
    check($seal->check($made, $now) === SealStatus::Valid, 'seal round trip');
    check($seal->check($seal->create($now - 1), $now) === SealStatus::TooFast, 'too fast');
    check($seal->check($seal->create($now - 7201), $now) === SealStatus::Expired, 'expired');
    [$time, $sig] = explode('.', $made);
    check($seal->check(($time - 100) . '.' . $sig, $now) === SealStatus::Invalid, 'changed time is forged');
    check($seal->check($time . '.' . strrev($sig), $now) === SealStatus::Invalid, 'changed signature is forged');
    check($seal->check($made . "\n", $now) === SealStatus::Invalid, 'seal with trailing newline is rejected');
    check($seal->check('', $now) === SealStatus::Invalid, 'empty seal is invalid');
    check($seal->check('abc', $now) === SealStatus::Invalid, 'garbage seal is invalid');
    check((new Seal(new Config($secretB)))->check($made, $now) === SealStatus::Invalid, 'seal from another secret is invalid');
    $noMax = new Seal(new Config($secretA, maxSeconds: 0));
    check($noMax->check($noMax->create($now - 10_000_000), $now) === SealStatus::Valid, 'max 0 disables expiry');

    // --- Field names
    $other = new Config($secretB);
    check($config->sealField !== $other->sealField, 'seal field name differs per secret');
    check($config->emptyField !== $other->emptyField, 'empty field name differs per secret');
    check($config->emptyClass !== $other->emptyClass, 'class name differs per secret');
    $words = ['honeypot', 'honey', 'bot', 'spam', 'trap'];
    $names = strtolower(implode(' ', [$config->sealField, $config->emptyField, $config->emptyClass]));
    $html = strtolower((new Fields($config))->html($now) . (new Fields($config, false))->html($now));
    foreach ($words as $word) {
        check(!str_contains($names, $word), "names contain no '$word'");
        check(!str_contains($html, $word), "html contains no '$word'");
    }

    // --- Fields html
    $html = (new Fields($config))->html($now);
    check(str_contains($html, 'name="' . $config->sealField . '"'), 'html has seal input');
    check(str_contains($html, 'tabindex="-1"') && str_contains($html, 'autocomplete="off"'), 'html has tabindex and autocomplete');
    check(str_contains($html, 'aria-hidden="true"') && str_contains($html, 'Bitte leer lassen / leave empty'), 'html has aria-hidden and label');
    check(str_contains($html, 'style="'), 'inline style by default');
    check(!str_contains((new Fields($config, false))->html($now), 'style='), 'class only without inline style');
    check(str_contains((new Fields($config, label: 'Nicht <ausfüllen>'))->html($now), 'Nicht &lt;ausfüllen&gt;'), 'label is a parameter and escaped');

    // --- Guard
    $limiter = new FileRateLimiter($dir, $config, 5, 3600);
    $guard = new Guard($config, $limiter);
    $post = fn (string|array $sealValue, array $extra = []): array => [$config->sealField => $sealValue] + $extra;

    $v = $guard->inspect($post($seal->create($now - 10)), '203.0.113.7', $now);
    check($v->isPass() && $v->reasons === [], 'valid seal passes');

    $v = $guard->inspect($post($seal->create($now - 1)), '198.51.100.1', $now);
    check($v->isFlag() && $v->reasons === [Reason::TooFast], 'too fast is flagged');

    $v = $guard->inspect($post($seal->create($now - 9000)), '198.51.100.2', $now);
    check($v->isFlag() && $v->reasons === [Reason::Expired], 'expired is flagged');

    $v = $guard->inspect([], '198.51.100.3', $now);
    check($v->isDrop() && $v->reasons === [Reason::InvalidSeal], 'missing seal is dropped');

    $v = $guard->inspect($post('1.' . str_repeat('0', 64)), '198.51.100.3', $now);
    check($v->isDrop() && $v->reasons === [Reason::InvalidSeal], 'forged seal is dropped');

    $v = $guard->inspect($post([]), '198.51.100.3', $now);
    check($v->isDrop() && $v->reasons === [Reason::InvalidSeal], 'seal as array is dropped');

    // six honeypot drops from one IP do not use up the limit: the seventh, honest request passes
    for ($i = 0; $i < 6; $i++) {
        $v = $guard->inspect($post($seal->create($now - 10), [$config->emptyField => 'x']), '198.51.100.4', $now);
        check($v->isDrop() && $v->reasons === [Reason::Honeypot], "filled empty field is dropped ($i)");
    }
    $v = $guard->inspect($post($seal->create($now - 10)), '198.51.100.4', $now);
    check($v->isPass(), 'dropped requests do not count');

    // --- Rate limit: 5 per hour, then drop, window resets
    $rateIp = '192.0.2.55';
    for ($i = 1; $i <= 5; $i++) {
        $v = $guard->inspect($post($seal->create($now - 10)), $rateIp, $now + $i);
        check(!$v->isDrop(), "request $i of 5 is accepted");
    }
    for ($i = 6; $i <= 8; $i++) {
        $v = $guard->inspect($post($seal->create($now - 10)), $rateIp, $now + $i);
        check($v->isDrop() && $v->reasons === [Reason::RateLimited], "request $i is rate limited");
    }
    $later = $now + 3700;
    $v = $guard->inspect($post($seal->create($later - 10)), $rateIp, $later);
    check($v->isPass(), 'rate_limited requests did not count: window resets after one hour');

    // --- attempt() directly
    $direct = new FileRateLimiter($dir . '/direct', $config, 2, 100);
    check($direct->attempt('192.0.2.9', 1000) && $direct->attempt('192.0.2.9', 1001), 'attempt accepts up to the limit');
    check(!$direct->attempt('192.0.2.9', 1002), 'attempt refuses over the limit');
    check($direct->attempt('192.0.2.10', 1002), 'attempt counts per IP');
    check($direct->attempt('192.0.2.9', 1200), 'attempt accepts again after the window');

    // --- IPv6 /64 and IPv4-mapped
    $v6 = new FileRateLimiter($dir . '/v6', $config, 2, 100);
    check($v6->attempt('2001:db8:1:2::1', 1000) && $v6->attempt('2001:db8:1:2:ffff::9', 1000), 'IPv6 same /64 shares the limit (counted)');
    check(!$v6->attempt('2001:db8:1:2:abcd::5', 1000), 'IPv6 same /64 shares the limit (refused)');
    check($v6->attempt('2001:db8:1:3::1', 1000), 'IPv6 other /64 has its own limit');
    check($v6->attempt('198.51.100.20', 1000) && $v6->attempt('::ffff:198.51.100.20', 1000)
        && !$v6->attempt('198.51.100.20', 1000), 'IPv4-mapped IPv6 counts as the IPv4');

    // --- purge
    $purge = new FileRateLimiter($dir . '/purge', $config, 5, 3600);
    $purge->attempt('192.0.2.30', $now);
    $purge->attempt('192.0.2.31', $now);
    check($purge->purge() === 0, 'purge keeps fresh files');
    $old = glob($dir . '/purge/*.rl')[0];
    touch($old, time() - 7200);
    check($purge->purge() === 1 && count(glob($dir . '/purge/*.rl')) === 1, 'purge deletes expired files only');

    // --- unwritable storage
    $blocker = $dir . '/blocker';
    file_put_contents($blocker, 'x');
    $broken = new FileRateLimiter($blocker . '/sub', $config);
    check(throws(fn () => $broken->attempt('192.0.2.40', $now)), 'unwritable directory throws RuntimeException');
    check(throws(fn () => (new Guard($config, $broken))->inspect($post($seal->create($now - 10)), '192.0.2.40', $now)), 'Guard passes the storage exception on');

    // --- IP not stored in clear
    $stored = '';
    foreach (array_merge(glob($dir . '/*.rl') ?: [], glob($dir . '/*/*.rl') ?: []) as $file) {
        $stored .= basename($file) . "\n" . file_get_contents($file) . "\n";
    }
    check($stored !== '', 'storage directories have files');
    foreach (['203.0.113.7', '192.0.2.55', '198.51.100.1', '2001:db8:1:2', '2001:db8'] as $address) {
        check(!str_contains($stored, $address), "IP $address not in storage");
        check(!str_contains($stored, hash('sha256', $address)), "plain hash of $address not in storage");
    }

    // --- Night (optional, off by default)
    $nightTime = $now - 5 * 3600; // 03:00 UTC
    $nightGuard = new Guard(new Config($secretA, nightHours: [0, 5]), new FileRateLimiter($dir . '/n', $config));
    $v = $nightGuard->inspect($post($seal->create($nightTime - 10)), '192.0.2.1', $nightTime);
    check($v->isFlag() && $v->reasons === [Reason::Night], 'night is flagged when on');
    $v = $guard->inspect($post($seal->create($nightTime - 10)), '192.0.2.2', $nightTime);
    check($v->isPass(), 'night is off by default');
    $wrap = new Guard(new Config($secretA, nightHours: [22, 5]), new FileRateLimiter($dir . '/w', $config));
    $v = $wrap->inspect($post($seal->create($nightTime - 10)), '192.0.2.3', $nightTime);
    check($v->isFlag(), 'night window wraps midnight');
    $v = $wrap->inspect($post($seal->create($now - 10)), '192.0.2.4', $now);
    check($v->isPass(), 'daytime passes with night on');

    // --- Input
    check(Input::singleLine("a\r\nBcc: x@example.com") === false, 'singleLine rejects CRLF');
    check(Input::singleLine("a\nb") === false, 'singleLine rejects LF');
    check(Input::singleLine("a\rb") === false, 'singleLine rejects CR');
    check(Input::singleLine('  Hello ') === 'Hello', 'singleLine trims');
    check(Input::stripControl("a\x00b\x07c\td\n") === "abc\td\n", 'stripControl keeps tab and newline');
} finally {
    removeDir($dir);
}

foreach ($failures as $failure) {
    echo "FAIL: $failure\n";
}
echo $failures === [] ? "$count checks\nOK\n" : count($failures) . " of $count checks failed\n";
exit($failures === [] ? 0 : 1);
