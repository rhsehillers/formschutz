<?php

declare(strict_types=1);

namespace Formschutz;

/**
 * N requests per window and IP, one file per IP, checked and counted in one locked step.
 * The file name is a keyed HMAC of the IP (IPv6: of its /64 prefix): the IP is stored nowhere.
 * Use one directory per limiter, outside the web root (or with all access denied). The directory may hold only
 * this limiter's files; purge() deletes every *.rl file in it that is older than one window.
 */
final class FileRateLimiter implements RateLimiter
{
    public function __construct(
        private readonly string $dir,
        private readonly Config $config,
        private readonly int $max = 5,
        private readonly int $windowSeconds = 3600,
    ) {
        if ($max < 1 || $windowSeconds < 1) {
            throw new \InvalidArgumentException('Formschutz: max and windowSeconds must be at least 1.');
        }
    }

    public function attempt(string $ip, int $now): bool
    {
        if (!is_dir($this->dir) && !@mkdir($this->dir, 0700, true) && !is_dir($this->dir)) {
            throw new \RuntimeException('Formschutz: cannot create directory ' . $this->dir);
        }
        $handle = @fopen($this->file($ip), 'c+b');
        if ($handle === false) {
            throw new \RuntimeException('Formschutz: cannot open a file in ' . $this->dir);
        }
        try {
            if (!flock($handle, LOCK_EX)) {
                throw new \RuntimeException('Formschutz: cannot lock a file in ' . $this->dir);
            }
            $times = $this->parse((string) stream_get_contents($handle), $now);
            if (count($times) >= $this->max) {
                return false;
            }
            $times[] = $now;
            $data = implode("\n", $times);
            if (!ftruncate($handle, 0) || !rewind($handle) || fwrite($handle, $data) !== strlen($data) || !fflush($handle)) {
                throw new \RuntimeException('Formschutz: cannot write in ' . $this->dir);
            }
        } finally {
            flock($handle, LOCK_UN);
            fclose($handle);
        }
        if (random_int(1, 50) === 1) {
            $this->purge();
        }
        return true;
    }

    /**
     * Deletes files not changed for one window. Runs now and then by itself after a submission; call it from a
     * cron job (hourly) so that data of a quiet site is removed too.
     *
     * @return int number of files deleted
     */
    public function purge(): int
    {
        $limit = time() - $this->windowSeconds;
        $deleted = 0;
        foreach (glob($this->dir . '/*.rl') ?: [] as $file) {
            $changed = @filemtime($file);
            // a concurrent purge may have removed the file already; then unlink fails and is not counted
            if ($changed !== false && $changed < $limit && @unlink($file)) {
                $deleted++;
            }
        }
        return $deleted;
    }

    /** @return list<int> timestamps inside the window */
    private function parse(string $content, int $now): array
    {
        $all = $content === '' ? [] : array_map('intval', explode("\n", $content));
        return array_values(array_filter($all, fn (int $t): bool => $t > $now - $this->windowSeconds));
    }

    private function file(string $ip): string
    {
        // keyed HMAC, not a plain hash: a plain SHA-256 of an IPv4 address can be reversed by trying all 2^32
        return $this->dir . '/' . $this->config->derive('ip:' . $this->normalise($ip)) . '.rl';
    }

    /** IPv6 clients usually own a whole /64, so the prefix is the unit; IPv4-mapped IPv6 counts as IPv4. */
    private function normalise(string $ip): string
    {
        $packed = @inet_pton($ip);
        if ($packed === false || strlen($packed) !== 16) {
            return $ip;
        }
        if (str_starts_with($packed, str_repeat("\0", 10) . "\xff\xff")) {
            return (string) inet_ntop(substr($packed, 12));
        }
        return 'v6:' . bin2hex(substr($packed, 0, 8));
    }
}
