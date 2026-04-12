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
        $panel->pages([
            Terminal::class,
            Sessions::class,
        ]);
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
