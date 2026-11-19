<?php

declare(strict_types=1);

namespace Formschutz;

interface RateLimiter
{
    /**
     * One atomic step: if the IP is under its limit, record this request and return true; otherwise return false
     * and record nothing.
     *
     * @throws \RuntimeException if the store cannot be used
     */
    public function attempt(string $ip, int $now): bool;
}
