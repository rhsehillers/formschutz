<?php

declare(strict_types=1);

namespace Formschutz;

/**
 * Settings shared by Seal, Guard, Fields and FileRateLimiter.
 * Field names are derived from the secret, so they differ on every site and cannot be targeted by name.
 */
final class Config
{
    public readonly string $sealField;
    public readonly string $emptyField;
    public readonly string $emptyClass;

    /**
     * @param string              $secret      at least 32 bytes, e.g. bin2hex(random_bytes(32)); never commit it
     * @param int                 $minSeconds  a form submitted faster than this is flagged (too_fast)
     * @param int                 $maxSeconds  a form older than this is flagged (expired); 0 = never (cached pages)
     * @param array{int,int}|null $nightHours  [from, to) in whole hours of $timezone, e.g. [0, 5]; null = off.
     *                                         from > to wraps midnight, e.g. [22, 5]
     * @param string              $timezone    timezone for $nightHours
     * @param string|null         $sealField   override the generated name of the hidden seal field
     * @param string|null         $emptyField  override the generated name of the field that must stay empty
     */
    public function __construct(
        #[\SensitiveParameter] private readonly string $secret,
        public readonly int $minSeconds = 4,
        public readonly int $maxSeconds = 7200,
        public readonly ?array $nightHours = null,
        public readonly string $timezone = 'UTC',
        ?string $sealField = null,
        ?string $emptyField = null,
    ) {
        if (strlen($secret) < 32) {
            throw new \InvalidArgumentException('Formschutz: secret must be at least 32 bytes.');
        }
        if ($minSeconds < 0 || $maxSeconds < 0 || ($maxSeconds !== 0 && $maxSeconds <= $minSeconds)) {
            throw new \InvalidArgumentException('Formschutz: maxSeconds must be 0 or greater than minSeconds.');
        }
        if ($nightHours !== null) {
            $hours = array_values($nightHours);
            if (count($hours) !== 2 || !is_int($hours[0]) || !is_int($hours[1])
                || $hours[0] < 0 || $hours[0] > 23 || $hours[1] < 0 || $hours[1] > 24) {
                throw new \InvalidArgumentException('Formschutz: nightHours must be [from 0-23, to 0-24].');
            }
        }
        try {
            new \DateTimeZone($timezone);
        } catch (\Exception $e) {
            throw new \InvalidArgumentException('Formschutz: unknown timezone: ' . $timezone, 0, $e);
        }
        $this->sealField = $sealField ?? $this->name('seal');
        $this->emptyField = $emptyField ?? $this->name('empty');
        $this->emptyClass = $this->name('class');
        foreach ([$this->sealField, $this->emptyField] as $field) {
            if (preg_match('/^[A-Za-z_][\w-]*$/', $field) !== 1) {
                throw new \InvalidArgumentException('Formschutz: invalid field name: ' . $field);
            }
        }
        if ($this->sealField === $this->emptyField) {
            throw new \InvalidArgumentException('Formschutz: the two field names must differ.');
        }
    }

    /** HMAC of a purpose string with the secret; the secret itself never leaves this class. */
    public function derive(string $purpose): string
    {
        return hash_hmac('sha256', $purpose, $this->secret);
    }

    private function name(string $purpose): string
    {
        return 'f_' . substr($this->derive('name:' . $purpose), 0, 8);
    }
}
