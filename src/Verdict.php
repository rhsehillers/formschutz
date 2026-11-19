<?php

declare(strict_types=1);

namespace Formschutz;

/**
 * Result of Guard::inspect().
 *  Pass: looks fine.
 *  Flag: probably human but unusual; process it, mark it for review (reasons: TooFast, Expired, Night).
 *  Drop: treat as a bot; show the normal success page, process nothing (reason: InvalidSeal, Honeypot, RateLimited).
 */
final class Verdict
{
    /** @param list<Reason> $reasons */
    private function __construct(public readonly Outcome $outcome, public readonly array $reasons = [])
    {
    }

    public static function pass(): self
    {
        return new self(Outcome::Pass);
    }

    public static function flag(Reason ...$reasons): self
    {
        return new self(Outcome::Flag, array_values($reasons));
    }

    public static function drop(Reason $reason): self
    {
        return new self(Outcome::Drop, [$reason]);
    }

    public function isPass(): bool
    {
        return $this->outcome === Outcome::Pass;
    }

    public function isFlag(): bool
    {
        return $this->outcome === Outcome::Flag;
    }

    public function isDrop(): bool
    {
        return $this->outcome === Outcome::Drop;
    }
}
