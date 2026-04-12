<?php

declare(strict_types=1);

namespace App\JabaliTerminal;

use App\JabaliTerminal\Http\Controllers\TerminalSessionController;
use App\JabaliTerminal\Pages\Sessions;
use App\JabaliTerminal\Pages\Terminal;
use Filament\Contracts\Plugin;
use Filament\Panel;
use Illuminate\Cache\RateLimiting\Limit;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\RateLimiter;
use Illuminate\Support\Facades\Route;
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
        $viewPath = app_path('JabaliTerminal/views');
        if (is_dir($viewPath)) {
            View::addNamespace('jabali-terminal', $viewPath);
        }

        // Rate limiter for the session-mint endpoint. Key is composed of
        // admin id + IP so a single compromised admin session can't burn
        // through tokens from many vantage points simultaneously, and a
        // single IP probing a list of admin ids is still capped per-admin.
        RateLimiter::for('jabali-terminal-session', function (Request $request): Limit {
            $user = $request->user('admin') ?? $request->user();
            $adminId = $user?->getAuthIdentifier() ?? 'guest';

            return Limit::perMinute(3)->by($adminId.'|'.$request->ip());
        });

        // Route registered here (not in the parent panel's routes/web.php)
        // so removing the addon also removes the endpoint. The route sits
        // under the same /jabali-admin prefix Filament uses so the session
        // cookie + CSRF token are scoped correctly.
        Route::middleware([
            'web',
            'auth:admin',
            'throttle:jabali-terminal-session',
        ])
            ->prefix('jabali-admin')
            ->post('terminal/session', TerminalSessionController::class)
            ->name('jabali-terminal.session');
    }
}
