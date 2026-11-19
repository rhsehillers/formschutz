<?php

declare(strict_types=1);

namespace Formschutz;

enum SealStatus
{
    case Valid;
    case Invalid;
    case TooFast;
    case Expired;
}
