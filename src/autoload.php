<?php

declare(strict_types=1);

// For use without Composer: require this file once.
spl_autoload_register(static function (string $class): void {
    $file = __DIR__ . '/' . substr($class, strlen('Formschutz\\')) . '.php';
    if (str_starts_with($class, 'Formschutz\\') && is_file($file)) {
        require $file;
    }
});
