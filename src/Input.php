<?php

declare(strict_types=1);

namespace Formschutz;

/** Helpers for mail headers: never put raw form input into a header. */
final class Input
{
    /** Returns the trimmed value, or false if it contains CR or LF (header injection). */
    public static function singleLine(string $value): string|false
    {
        return preg_match('/[\r\n]/', $value) === 1 ? false : trim($value);
    }

    /** Removes control characters (NUL, backspace, ...) but keeps tab, LF and CR for message bodies. */
    public static function stripControl(string $value): string
    {
        return (string) preg_replace('/[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]/', '', $value);
    }
}
