<?php

declare(strict_types=1);

namespace Formschutz;

/**
 * The HTML to put inside your <form>: a hidden seal input and a field that real visitors never fill.
 *
 * Hiding the second field:
 *  - $inlineStyle = true (default): an inline style moves it off-screen. Nothing else to do.
 *  - $inlineStyle = false: only the class is set. Style it yourself, e.g. for a strict Content-Security-Policy:
 *      .<className> { position: absolute; left: -10000px; width: 1px; height: 1px; overflow: hidden; }
 *    Do not use display:none; some bots skip such fields.
 *
 * The markup has a fixed structure (hidden input, div, label, text input). Field names and class differ per site,
 * but a bot written for this package could still recognise the structure.
 */
final class Fields
{
    private readonly Seal $seal;

    public function __construct(
        private readonly Config $config,
        private readonly bool $inlineStyle = true,
        private readonly string $label = 'Bitte leer lassen / leave empty',
    ) {
        $this->seal = new Seal($config);
    }

    public function className(): string
    {
        return $this->config->emptyClass;
    }

    public function html(?int $now = null): string
    {
        $c = $this->config;
        $style = $this->inlineStyle
            ? ' style="position:absolute;left:-10000px;width:1px;height:1px;overflow:hidden"'
            : '';
        $seal = self::e($c->sealField);
        $empty = self::e($c->emptyField);
        return '<input type="hidden" name="' . $seal . '" value="' . self::e($this->seal->create($now ?? time())) . '">' . "\n"
            . '<div class="' . self::e($c->emptyClass) . '"' . $style . ' aria-hidden="true">'
            . '<label for="' . $empty . '">' . self::e($this->label) . '</label>'
            . '<input type="text" id="' . $empty . '" name="' . $empty . '" value="" tabindex="-1" autocomplete="off">'
            . '</div>';
    }

    private static function e(string $s): string
    {
        return htmlspecialchars($s, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
    }
}
