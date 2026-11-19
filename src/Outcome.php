<?php

declare(strict_types=1);

namespace Formschutz;

enum Outcome
{
    case Pass;
    case Flag;
    case Drop;
}
