<?php

declare(strict_types=1);

namespace App\JabaliTerminal\Pages;

use App\JabaliTerminal\Http\PreventFramingMiddleware;
use App\JabaliTerminal\JabaliTerminalClient;
use BackedEnum;
use Filament\Pages\Page;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Hash;
use Laravel\Fortify\Contracts\TwoFactorAuthenticationProvider;

/**
 * Browser root terminal page.
 *
 * Security posture (see docs/SECURITY.md):
 *  - canAccess() hard-fails for non-admins BEFORE mount runs.
 *  - openSession() re-verifies the admin's own password AND a fresh 2FA code
 *    every time; session cookie alone is not enough to open a PTY.
 *  - The token returned by the daemon is sent back to the browser but MUST
 *    live only in JavaScript memory — the Blade view never renders it
 *    into the DOM and the route never persists it.
 *  - SEC-REV-8: PreventFramingMiddleware pins X-Frame-Options: DENY and
 *    CSP frame-ancestors 'none' on every response.
 *  - Step 6 tightens auth further (rate limiting, lockout, dedicated route);
 *    this page provides the minimal round-trip wiring.
 */
class Terminal extends Page
{
    protected static string|BackedEnum|null $navigationIcon = 'heroicon-o-command-line';

    protected static ?string $navigationGroup = 'Tools';

    protected static ?int $navigationSort = 50;

    protected static ?string $slug = 'terminal';

    protected static ?string $title = 'Root Terminal';

    protected string $view = 'jabali-terminal::terminal';

    /**
     * Applied by Filament when the route is built.
     *
     * @var string|array<string>
     */
    protected static string|array $routeMiddleware = [PreventFramingMiddleware::class];

    public static function canAccess(): bool
    {
        $user = auth()->user();

        return $user !== null && method_exists($user, 'isAdmin') && $user->isAdmin();
    }

    public function mount(): void
    {
        abort_unless(static::canAccess(), 403);
    }

    /**
     * Livewire entry point for the re-auth modal.
     *
     * Returns a JSON-shaped array describing the minted session, or throws
     * ValidationException-equivalent data so the Blade view can display the
     * error without leaking whether the password or the 2FA code was wrong.
     *
     * @return array{ok: bool, ws_url?: string, token?: string, expires_at?: int, error?: string}
     */
    public function openSession(string $password, string $twoFactorCode, Request $request): array
    {
        $user = auth()->user();

        if ($user === null || ! method_exists($user, 'isAdmin') || ! $user->isAdmin()) {
            return ['ok' => false, 'error' => 'forbidden'];
        }

        // Re-verify the admin's own password. Same generic error for both
        // this and a bad 2FA code so the UI does not reveal which failed.
        if (! Hash::check($password, (string) $user->getAuthPassword())) {
            return ['ok' => false, 'error' => 'invalid credentials'];
        }

        // 2FA is MANDATORY (docs/SECURITY.md). No opt-out path.
        if (empty($user->two_factor_secret)) {
            return ['ok' => false, 'error' => '2fa required'];
        }

        /** @var TwoFactorAuthenticationProvider $provider */
        $provider = app(TwoFactorAuthenticationProvider::class);
        $decryptedSecret = decrypt($user->two_factor_secret);
        if (! $provider->verify($decryptedSecret, $twoFactorCode)) {
            return ['ok' => false, 'error' => 'invalid credentials'];
        }

        $client = JabaliTerminalClient::getInstance();
        if (! $client->isAvailable()) {
            return ['ok' => false, 'error' => 'daemon unavailable'];
        }

        $session = $client->requestSession((int) $user->getAuthIdentifier(), (string) $request->ip());
        if ($session === null) {
            return ['ok' => false, 'error' => 'session mint failed'];
        }

        return [
            'ok' => true,
            'ws_url' => (string) $session['ws_url'],
            'token' => (string) $session['token'],
            'expires_at' => (int) $session['expires_at'],
        ];
    }
}
