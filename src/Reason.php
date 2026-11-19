<?php

declare(strict_types=1);

namespace Formschutz;

/** Why a request was flagged or dropped. The string value is stable and safe for subjects and logs. */
enum Reason: string
{
    // Flag
    case TooFast = 'too_fast';
    case Expired = 'expired';
    case Night = 'night';
    case LimiterError = 'limiter_error'; // never set by Guard; for callers that catch a storage failure
    // Drop
    case InvalidSeal = 'invalid_seal';
    case Honeypot = 'honeypot';
    case RateLimited = 'rate_limited';
}
