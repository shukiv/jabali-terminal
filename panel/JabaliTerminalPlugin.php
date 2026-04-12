<?php

declare(strict_types=1);

namespace App\JabaliTerminal;

use App\JabaliTerminal\Pages\Sessions;
use App\JabaliTerminal\Pages\Terminal;
use Filament\Contracts\Plugin;
use Filament\Panel;
use Illuminate\Support\Facades\View;

/**
 * Jabali Terminal — in-panel root shell.
 *
 * Autodiscovered by AdminPanelProvider via class_exists() so the panel boots
 * cleanly when the addon is uninstalled. Do NOT sed AdminPanelProvider.php
 * to register this plugin — the panel already has the class_exists() guard.
 *
 * Security note: this plugin registers a page that hands a root PTY to the
 * browser. All auth + audit concerns live in the daemon and in Pages\Terminal;
 * this file only wires discovery.
 */
class JabaliTerminalPlugin implements Plugin
{
    public static function make(): static
    {
        return app(static::class);
    }

    public static function get(): static
    {
        return filament(static::class);
    }

    public function getId(): string
    {
        return 'jabali-terminal';
    }

    public function register(Panel $panel): void
    {
        $pages = [Terminal::class];
        // Sessions is the read-only audit-log browser. Hiding it doesn't
        // affect logging — the daemon still writes + HMAC-seals every
        // transcript under /var/log/jabali-terminal/sessions/. Default on
        // so existing installs behave as before; ops can flip it off in
        // /etc/jabali-terminal/jabali-terminal.conf if they prefer the
        // Filament nav to stay clean.
        if (self::configBool('sessions_ui_enabled', true)) {
            $pages[] = Sessions::class;
        }
        $panel->pages($pages);
    }

    /**
     * Parse a boolean-ish key from /etc/jabali-terminal/jabali-terminal.conf.
     * Deliberately kept here (not in JabaliTerminalClient) because it runs
     * during panel boot before the container is warm, and because the
     * Sessions UI toggle has nothing to do with daemon comms.
     */
    private static function configBool(string $key, bool $default): bool
    {
        $configFile = '/etc/jabali-terminal/jabali-terminal.conf';
        if (! is_readable($configFile)) {
            return $default;
        }
        $content = @file_get_contents($configFile);
        if ($content === false) {
            return $default;
        }
        $pattern = '/^'.preg_quote($key, '/').'="([^"]*)"$/m';
        if (preg_match($pattern, $content, $m) !== 1) {
            return $default;
        }
        $v = strtolower(trim($m[1]));
        if (in_array($v, ['false', '0', 'no', 'off', ''], true)) {
            return false;
        }
        if (in_array($v, ['true', '1', 'yes', 'on'], true)) {
            return true;
        }
        return $default;
    }

    public function boot(Panel $panel): void
    {
        // View namespace only. Route registration + RateLimiter live in
        // JabaliTerminalServiceProvider, registered via the parent panel's
        // bootstrap/providers.php (class_exists-gated). Plugin::boot runs
        // from inside the panel middleware stack — too late for routes,
        // and not at all during CLI commands like `route:cache`.
        $viewPath = app_path('JabaliTerminal/views');
        if (is_dir($viewPath)) {
            View::addNamespace('jabali-terminal', $viewPath);
        }
    }
}
