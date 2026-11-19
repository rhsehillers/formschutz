# Formschutz

Bot-Schutz für einfache PHP-Formulare. Ohne CAPTCHA, Cookies, JavaScript und Aufrufe bei Dritten. PHP 8.1+, keine Abhängigkeiten, MIT.

English: [README.md](README.md)

## Was es tut

Drei Prüfungen bei jedem Absenden, in dieser Reihenfolge:

1. **Leeres Feld.** Ein verstecktes Feld, das echte Besucher nie ausfüllen. Ausgefüllt heißt Bot.
2. **Zeitsiegel.** Ein signierter Zeitstempel (HMAC-SHA256) in einem versteckten Feld. Gefälscht oder fehlend heißt Bot. Nach weniger als 4 Sekunden abgeschickt heißt „zu schnell“, älter als 2 Stunden heißt „abgelaufen“.
3. **Begrenzung.** 5 angenommene Anfragen pro Stunde und IP-Adresse.

Die Feldnamen werden aus Ihrem Geheimnis erzeugt und sind auf jeder Seite anders. Ein Bot kann das Paket nicht über Feldnamen gezielt angreifen.

## Was es nicht tut

Es hält den Großteil ungezielter Bots auf. Ein gezielter Bot, der JavaScript ausführt, Ihr Formular liest und ein paar Sekunden wartet, kommt durch. Es prüft keine Nachrichteninhalte, ersetzt keine Eingabeprüfung und schützt nicht vor Menschen, die Spam von Hand schreiben.

Die Feldnamen sind pro Seite verschieden, der Aufbau des Markups (verstecktes Feld, div, Label, Textfeld) ist aber überall gleich; ein Bot, der für dieses Paket geschrieben wurde, könnte ihn erkennen.

Ein Siegel ist nicht einmalig. Dasselbe Siegel kann erneut gesendet werden, bis es älter als `maxSeconds` ist; danach wird eine Wiederholung als `expired` markiert, nicht verworfen. Die Begrenzung ist es, die Wiederholungen eindämmt.

## Pass, Flag, Drop

`Guard::inspect()` liefert ein `Verdict`:

| Ergebnis | Bedeutung | Ihre Reaktion |
|---|---|---|
| `Pass` | Sieht gut aus. | Verarbeiten. |
| `Flag` | Echt, aber ungewöhnlich: `Reason::TooFast`, `Expired` oder `Night` (optional, standardmäßig aus). | Verarbeiten und markieren, z. B. „PRÜFEN“ im Betreff. |
| `Drop` | `Reason::InvalidSeal`, `Honeypot` oder `RateLimited`. | Die normale Erfolgsseite zeigen. Nichts senden. |

Bots glauben, sie hätten Erfolg gehabt; echte, aber ungewöhnliche Anfragen werden markiert, nie verloren. Ein Bot sieht nie einen Fehler und hat keinen Anlass, sich anzupassen.

## Installation

Composer. Das Paket ist noch nicht auf Packagist; nutzen Sie das Repository direkt (URL ersetzen):

```json
{
    "repositories": [{"type": "vcs", "url": "https://github.com/rhsehillers/formschutz"}],
    "require": {"rhse/formschutz": "^0.1"}
}
```

Oder den Ordner `src/` kopieren und `require 'src/autoload.php';` einbinden.

## Schnellstart

```php
$config = new Formschutz\Config($secret);   // mind. 32 Bytes, nicht im Repository
$guard  = new Formschutz\Guard($config, new Formschutz\FileRateLimiter('/var/lib/myapp/contact-limits', $config));
$fields = new Formschutz\Fields($config);

echo $fields->html();                       // im <form>

// bei POST, nach Ihrer eigenen Prüfung:
$verdict = $guard->inspect($_POST, $_SERVER['REMOTE_ADDR']);
if ($verdict->isDrop()) { /* Erfolg anzeigen, nichts senden */ }
elseif ($verdict->isFlag()) { /* senden, markieren: $verdict->reasons */ }
else { /* senden */ }
```

Ein vollständiges Formular mit Post-Redirect-Get steht in [examples/contact.php](examples/contact.php), ein Geheimnis aus der Umgebung oder aus einer Datei außerhalb des Web-Ordners in [examples/config.example.php](examples/config.example.php). Ein Geheimnis erzeugen Sie mit `php -r "echo bin2hex(random_bytes(32));"`. Nie ins Repository legen.

Nur Anfragen, die als Pass oder Flag enden, zählen gegen die Begrenzung; ein Drop, auch `rate_limited`, zählt nichts. Rufen Sie `inspect()` nach Ihrer eigenen Prüfung auf, damit ein Besucher, der sich nur bei der E-Mail-Adresse vertippt hat, das Kontingent nicht verbraucht.

## Einstellungen

`new Config($secret, minSeconds: 4, maxSeconds: 7200, nightHours: null, timezone: 'UTC')`

- `maxSeconds: 0` schaltet das Ablaufen ab.
- `nightHours: [0, 5]` markiert Anfragen von 00:00 bis 04:59 Uhr in `timezone`. `[22, 5]` geht über Mitternacht.
- `sealField` und `emptyField` ersetzen die erzeugten Feldnamen.
- `new Fields($config, inlineStyle: true, label: 'Bitte leer lassen / leave empty')`: der Label-Text ist ein Parameter; nehmen Sie die Sprache Ihrer Seite.
- `FileRateLimiter($dir, $config, max: 5, windowSeconds: 3600)`. Für einen anderen Speicher implementieren Sie `RateLimiter` (eine Methode, `attempt()`).
- `Input::singleLine($s)` liefert den getrimmten Text oder `false`, wenn er CR oder LF enthält. Nutzen Sie es für alles, was in einen Mail-Header geht (Name, E-Mail-Adresse, Betreff). `Input::stripControl($s)` entfernt Steuerzeichen und lässt Tabulator und Zeilenumbrüche stehen.

## Das leere Feld verstecken

Standardmäßig setzt `Fields` einen Inline-Stil, der das Feld aus dem Bild schiebt. Verbietet Ihre Content-Security-Policy Inline-Stile, nutzen Sie `new Fields($config, inlineStyle: false)` und gestalten die Klasse selbst:

```css
.f_xxxxxxxx { position: absolute; left: -10000px; width: 1px; height: 1px; overflow: hidden; }
```

`$fields->className()` liefert den erzeugten Klassennamen. Vermeiden Sie `display:none`, manche Bots überspringen solche Felder. Das Feld hat `tabindex="-1"`, `autocomplete="off"`, einen Container mit `aria-hidden="true"` und ein Label für den seltenen Screenreader, der es erreicht.

## Seiten-Cache

Das Siegel enthält den Zeitpunkt, an dem das Formular erzeugt wurde. Liefert ein Cache die Seite stundenlang aus, tragen Besucher alte Siegel. Setzen Sie `maxSeconds: 0` oder rendern Sie das Formular ohne Cache. Bei `maxSeconds: 0` läuft ein Siegel nie ab, ein Bot kann es also wiederverwenden; leeres Feld und Begrenzung greifen weiter.

## Hinter Proxy oder CDN

`REMOTE_ADDR` ist dann die Adresse des Proxys, und alle teilen sich ein Kontingent. Nur wenn `REMOTE_ADDR` Ihr eigener Proxy ist, nehmen Sie die Client-IP aus dem Eintrag, den Ihr Proxy angehängt hat (der letzte, rechte Eintrag von `X-Forwarded-For`), oder aus einem Header, den Ihr Proxy selbst setzt (z. B. `X-Real-IP`). Vertrauen Sie dem Header nie, wenn die Anfrage von anderswo kommt: Jeder kann eine beliebige IP hineinschreiben.

## Geteilte Adressen und IPv6

Viele Besucher können sich eine IPv4-Adresse teilen (Firmennetz, Mobilfunk). Bei 5 pro Stunde kann eine stark genutzte gemeinsame Adresse an die Grenze stoßen; diese Anfragen werden still verworfen. Wenn das für Sie zählt, protokollieren Sie Drops mit `Reason::RateLimited` (`error_log`) und erhöhen Sie `max`.

IPv6-Adressen werden nach ihrem /64-Präfix gezählt, weil ein Anschluss meist ein ganzes /64 besitzt. IPv4-gemappte IPv6-Adressen zählen als die IPv4-Adresse.

## Speicher und Bereinigung

`FileRateLimiter` legt je IP-Adresse eine Datei in seinem Ordner an. Nutzen Sie einen Ordner je Limiter, außerhalb des Web-Ordners (oder mit gesperrtem Zugriff) und für nichts anderes: `purge()` löscht dort jede `*.rl`-Datei, die älter als ein Zeitraum ist.

Abgelaufene Dateien werden zufällig nach etwa jeder fünfzigsten angenommenen Anfrage gelöscht, sowie durch `purge()`. Eine ruhige Seite behält eine Datei deshalb unter Umständen länger als einen Zeitraum. Rufen Sie `purge()` per Cronjob auf, empfohlen stündlich:

```php
// bin/purge.php
(new Formschutz\FileRateLimiter('/var/lib/myapp/contact-limits', $config))->purge();
```

## Wenn der Speicher ausfällt

Lässt sich der Ordner nicht anlegen oder beschreiben, wirft `Guard::inspect()` eine `RuntimeException`. Entscheiden Sie, was Ihre Seite dann tut: Das Beispiel fängt sie, schreibt `error_log` und behandelt die Anfrage als `Verdict::flag(Reason::LimiterError)`, sodass eine echte Nachricht nicht verloren geht, aber markiert ist. Die Alternative ist, die Anfrage abzulehnen. Die Ausnahme zum Besucher durchschlagen zu lassen ist die schlechteste Wahl.

## Datenschutz

- Keine Cookies, kein JavaScript, keine Aufrufe bei anderen Servern.
- Die Begrenzung legt je IP-Adresse (IPv6: je /64-Präfix) eine Datei an. Der Dateiname ist ein Schlüssel-Hash (HMAC-SHA256 mit Ihrem Geheimnis) der Adresse: Die Adresse ist pseudonymisiert und steht nirgends im Klartext. Das ist Pseudonymisierung, keine Anonymisierung: Wer das Geheimnis hat, kann eine Adresse mit einem Dateinamen abgleichen. Eine Datei enthält nur Zeitpunkte.
- Eine Datei wird gelöscht, wenn nach Ablauf des Zeitraums (Standard 1 Stunde) die zufällige Bereinigung bei einer späteren angenommenen Anfrage läuft, oder durch Ihren Cronjob mit `purge()`. Ohne Cron kann die Datei einer ruhigen Seite länger bleiben.
- Den Speicherordner außerhalb des Web-Ordners halten.
- Das Siegel enthält nur einen Zeitstempel.

Textbaustein für die Datenschutzerklärung (anpassen; **keine Rechtsberatung / not legal advice**):

> **Spam-Schutz im Kontaktformular.** Zum Schutz vor automatisierten Anfragen prüfen wir beim Absenden den Zeitpunkt des Seitenaufrufs (signierter Zeitstempel im Formular) und begrenzen die Zahl der Anfragen je Anschluss. Dafür speichern wir einen pseudonymisierten Hashwert Ihrer IP-Adresse (Schlüssel-Hash, HMAC) mit den Zeitpunkten der Anfragen. Der Eintrag wird regelmäßig, spätestens nach der nächsten Bereinigung (stündlich), gelöscht, wenn der Zeitraum von einer Stunde abgelaufen ist. Es werden keine Cookies gesetzt und keine Daten an Dritte übermittelt. Rechtsgrundlage ist Art. 6 Abs. 1 lit. f DSGVO (berechtigtes Interesse am Schutz des Formulars vor Missbrauch).
>
> **Spam protection in the contact form.** To protect against automated requests we check when the page was loaded (a signed timestamp in the form) and limit the number of requests per connection. For this we store a pseudonymised keyed hash (HMAC) of your IP address with the request times. The entry is deleted regularly, at the latest at the next clean-up (hourly), once the one-hour window has passed. No cookies are set and no data is passed to third parties. Legal basis: Art. 6(1)(f) GDPR (legitimate interest in protecting the form from abuse).

Der Baustein setzt den stündlichen `purge()` voraus. Betreiben Sie keinen, ändern Sie den Satz zur Löschung entsprechend.

## Tests

```
php tests/run.php
```

Die letzte Zeile lautet `OK`, wenn alles besteht.

## Lizenz

MIT, siehe [LICENSE](LICENSE).
