# Formschutz

Bot protection for plain PHP forms. No CAPTCHA, no cookies, no JavaScript, no third-party calls. PHP 8.1+, no dependencies, MIT.

Deutsch: [README.de.md](README.de.md)

## What it does

Three checks on every submission, in this order:

1. **Empty field.** A hidden field that real visitors never fill. Filled means bot.
2. **Time seal.** A signed timestamp (HMAC-SHA256) in a hidden input. Forged or missing means bot. Submitted within 4 seconds means "too fast", older than 2 hours means "expired".
3. **Rate limit.** 5 accepted submissions per hour and IP.

Field names are generated from your secret, so they differ on every site. A bot cannot target the package by field name.

## What it does not do

It stops the bulk of untargeted bots. A targeted bot that runs JavaScript, reads your form and waits a few seconds can pass. It does not check message content, is no replacement for input validation, and does not defend against people who write spam by hand.

Field names differ per site, but the markup structure (hidden input, div, label, text input) is the same everywhere; a bot written for this package could recognise it.

A seal is not single-use. The same seal can be sent again until it is older than `maxSeconds`; after that a replay is flagged as `expired`, not dropped. The rate limit is what bounds replays.

## Pass, Flag, Drop

`Guard::inspect()` returns a `Verdict`:

| Verdict | Meaning | What you do |
|---|---|---|
| `Pass` | Looks fine. | Process it. |
| `Flag` | Real but unusual: `Reason::TooFast`, `Expired`, or `Night` (optional, off by default). | Process it and mark it, e.g. "PRÜFEN" in the mail subject. |
| `Drop` | `Reason::InvalidSeal`, `Honeypot` or `RateLimited`. | Show the normal success page. Send nothing. |

Bots think they succeeded; real but unusual submissions are flagged, never lost. Because a bot never sees an error, it gets no signal to adapt to.

## Install

Composer. The package is not on Packagist yet; use the repository directly (replace the URL with the real one):

```json
{
    "repositories": [{"type": "vcs", "url": "https://github.com/rhsehillers/formschutz"}],
    "require": {"rhse/formschutz": "^0.1"}
}
```

Or copy the `src/` folder and `require 'src/autoload.php';`.

## Quick start

```php
$config = new Formschutz\Config($secret);   // at least 32 bytes, kept out of the repo
$guard  = new Formschutz\Guard($config, new Formschutz\FileRateLimiter('/var/lib/myapp/contact-limits', $config));
$fields = new Formschutz\Fields($config);

echo $fields->html();                       // inside your <form>

// on POST, after your own validation:
$verdict = $guard->inspect($_POST, $_SERVER['REMOTE_ADDR']);
if ($verdict->isDrop()) { /* show success, send nothing */ }
elseif ($verdict->isFlag()) { /* send, mark it: $verdict->reasons */ }
else { /* send */ }
```

A complete form with Post-Redirect-Get is in [examples/contact.php](examples/contact.php); a secret from the environment or a file outside the web root is in [examples/config.example.php](examples/config.example.php). Create a secret with `php -r "echo bin2hex(random_bytes(32));"`. Never commit it.

Only requests that end as Pass or Flag count against the rate limit; a Drop, including `rate_limited`, counts nothing. Call `inspect()` after your own validation, so a visitor who only mistyped an e-mail address does not use up the limit.

## Options

`new Config($secret, minSeconds: 4, maxSeconds: 7200, nightHours: null, timezone: 'UTC')`

- `maxSeconds: 0` turns the expiry off.
- `nightHours: [0, 5]` flags submissions from 00:00 to 04:59 in `timezone`. `[22, 5]` wraps midnight.
- `sealField` and `emptyField` override the generated field names.
- `new Fields($config, inlineStyle: true, label: 'Bitte leer lassen / leave empty')`: the label text is a parameter; use your site's language.
- `FileRateLimiter($dir, $config, max: 5, windowSeconds: 3600)`. Implement `RateLimiter` (one method, `attempt()`) for another store.
- `Input::singleLine($s)` returns the trimmed string, or `false` if it contains CR or LF. Use it for everything that goes into a mail header (name, e-mail address, subject). `Input::stripControl($s)` removes control characters and keeps tab and line breaks.

## Hiding the empty field

By default `Fields` adds an inline style that moves the field off-screen. If your Content-Security-Policy forbids inline styles, use `new Fields($config, inlineStyle: false)` and style the class yourself:

```css
.f_xxxxxxxx { position: absolute; left: -10000px; width: 1px; height: 1px; overflow: hidden; }
```

`$fields->className()` gives the generated class name. Avoid `display:none`, which some bots skip. The field has `tabindex="-1"`, `autocomplete="off"`, a wrapper with `aria-hidden="true"` and a label for the rare screen reader that reaches it.

## Page cache

The seal contains the time the form was rendered. If a cache serves the page for hours, visitors get old seals. Set `maxSeconds: 0`, or render the form uncached. With `maxSeconds: 0` a seal never expires, so a bot can reuse one; the rate limit and the empty field still apply.

## Behind a proxy or CDN

`REMOTE_ADDR` is then the proxy's address and everyone shares one limit. Only if `REMOTE_ADDR` is your own proxy, take the client IP from the entry your proxy appended (the rightmost entry of `X-Forwarded-For`) or from a header your proxy sets itself (for example `X-Real-IP`). Never trust that header when the request comes from anywhere else: anyone can write any IP into it.

## Shared addresses and IPv6

Many visitors can share one IPv4 address (company network, mobile carrier). With 5 per hour a busy shared address can hit the limit; those requests are dropped silently. If that matters for you, log `Reason::RateLimited` drops (`error_log`) and raise `max`.

IPv6 addresses are counted by their /64 prefix, because one household usually owns a whole /64. IPv4-mapped IPv6 addresses count as the IPv4 address.

## Storage and cleanup

`FileRateLimiter` keeps one file per IP in its directory. Use one directory per limiter, outside the web root (or with all access denied), used for nothing else: `purge()` deletes every `*.rl` file there that is older than one window.

Expired files are deleted by chance after about one in fifty accepted submissions, and by `purge()`. A quiet site may therefore keep a file longer than one window. Call `purge()` from a cron job, recommended hourly:

```php
// bin/purge.php
(new Formschutz\FileRateLimiter('/var/lib/myapp/contact-limits', $config))->purge();
```

## When storage fails

If the directory cannot be created or written, `Guard::inspect()` throws a `RuntimeException`. Decide what your site does: the example catches it, writes `error_log`, and treats the request as `Verdict::flag(Reason::LimiterError)`, so a real message is not lost but is marked. The other choice is to refuse the request. Letting the exception reach the visitor is the worst option.

## Privacy

- No cookies, no JavaScript, no requests to other servers.
- The rate limiter keeps one file per IP address (IPv6: per /64 prefix). The file name is a keyed hash (HMAC-SHA256 with your secret) of the address: the address is pseudonymised and stored nowhere in clear. This is pseudonymisation, not anonymisation: whoever has the secret can check a given address against a file name. A file holds only timestamps.
- A file is deleted at the next accepted submission after the window (1 hour by default) when the chance cleanup runs, or by your cron job calling `purge()`. Without cron, a file of a quiet site can stay longer.
- Keep the storage folder outside the web root.
- The seal holds only a timestamp.

Privacy policy snippet (adapt it; **not legal advice / keine Rechtsberatung**):

> **Spam-Schutz im Kontaktformular.** Zum Schutz vor automatisierten Anfragen prüfen wir beim Absenden den Zeitpunkt des Seitenaufrufs (signierter Zeitstempel im Formular) und begrenzen die Zahl der Anfragen je Anschluss. Dafür speichern wir einen pseudonymisierten Hashwert Ihrer IP-Adresse (Schlüssel-Hash, HMAC) mit den Zeitpunkten der Anfragen. Der Eintrag wird regelmäßig, spätestens nach der nächsten Bereinigung (stündlich), gelöscht, wenn der Zeitraum von einer Stunde abgelaufen ist. Es werden keine Cookies gesetzt und keine Daten an Dritte übermittelt. Rechtsgrundlage ist Art. 6 Abs. 1 lit. f DSGVO (berechtigtes Interesse am Schutz des Formulars vor Missbrauch).
>
> **Spam protection in the contact form.** To protect against automated requests we check when the page was loaded (a signed timestamp in the form) and limit the number of requests per connection. For this we store a pseudonymised keyed hash (HMAC) of your IP address with the request times. The entry is deleted regularly, at the latest at the next clean-up (hourly), once the one-hour window has passed. No cookies are set and no data is passed to third parties. Legal basis: Art. 6(1)(f) GDPR (legitimate interest in protecting the form from abuse).

The snippet assumes you run the hourly `purge()`. If you do not, change the sentence about deletion to match what you do.

## Tests

```
php tests/run.php
```

The last line is `OK` when everything passes.

## License

MIT, see [LICENSE](LICENSE).
