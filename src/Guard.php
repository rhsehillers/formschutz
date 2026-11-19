<?php

declare(strict_types=1);

namespace Formschutz;

/**
 * Checks a submitted form. Order: empty field -> seal -> rate limit. Bots never learn which check stopped them.
 * Only requests that end as Pass or Flag count against the rate limit; a Drop (also rate_limited) counts nothing.
 */
final class Guard
{
    private readonly Seal $seal;

    public function __construct(private readonly Config $config, private readonly RateLimiter $limiter)
    {
        $this->seal = new Seal($config);
    }

    /**
     * @param array<mixed> $post $_POST
     * @param string       $ip   the client IP (behind a proxy: see README)
     * @throws \RuntimeException if the rate limiter cannot use its store; see README "When storage fails"
     */
    public function inspect(array $post, string $ip, ?int $now = null): Verdict
    {
        $now ??= time();
        if (($post[$this->config->emptyField] ?? '') !== '') {
            return Verdict::drop(Reason::Honeypot);
        }
        $value = $post[$this->config->sealField] ?? '';
        $status = $this->seal->check(is_string($value) ? $value : '', $now);
        if ($status === SealStatus::Invalid) {
            return Verdict::drop(Reason::InvalidSeal);
        }
        // counted here, before the caller sends: a failing mail server must not open the door to unlimited retries
        if (!$this->limiter->attempt($ip, $now)) {
            return Verdict::drop(Reason::RateLimited);
        }

        $reasons = [];
        if ($status === SealStatus::TooFast) {
            $reasons[] = Reason::TooFast;
        } elseif ($status === SealStatus::Expired) {
            $reasons[] = Reason::Expired;
        }
        if ($this->isNight($now)) {
            $reasons[] = Reason::Night;
        }
        return $reasons === [] ? Verdict::pass() : Verdict::flag(...$reasons);
    }

    private function isNight(int $now): bool
    {
        if ($this->config->nightHours === null) {
            return false;
        }
        [$from, $to] = array_values($this->config->nightHours);
        $hour = (int) (new \DateTimeImmutable('@' . $now))
            ->setTimezone(new \DateTimeZone($this->config->timezone))->format('G');
        return $from <= $to ? $hour >= $from && $hour < $to : $hour >= $from || $hour < $to;
    }
}
