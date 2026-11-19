<?php

declare(strict_types=1);

namespace Formschutz;

/**
 * Signed timestamp for a hidden form field ("timestamp.signature", HMAC-SHA256).
 * No session, no cookie: the signature protects the time, so it cannot be forged or changed.
 * A seal is not single-use: it can be sent again until it is older than maxSeconds; after that a replay is
 * flagged as expired, not dropped. The rate limit is what bounds replays.
 */
final class Seal
{
    public function __construct(private readonly Config $config)
    {
    }

    public function create(int $now): string
    {
        return $now . '.' . $this->signature((string) $now);
    }

    public function check(string $seal, int $now): SealStatus
    {
        $parts = explode('.', $seal, 2);
        if (count($parts) !== 2 || preg_match('/^\d{1,12}\z/', $parts[0]) !== 1
            || !hash_equals($this->signature($parts[0]), $parts[1])) {
            return SealStatus::Invalid;
        }
        $age = $now - (int) $parts[0];
        if ($age < $this->config->minSeconds) {
            return SealStatus::TooFast;
        }
        if ($this->config->maxSeconds !== 0 && $age > $this->config->maxSeconds) {
            return SealStatus::Expired;
        }
        return SealStatus::Valid;
    }

    private function signature(string $timestamp): string
    {
        // prefix separates this use of the secret from the others (IP hash, field names)
        return $this->config->derive('seal:' . $timestamp);
    }
}
