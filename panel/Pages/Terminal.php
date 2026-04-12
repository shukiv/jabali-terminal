<?php

declare(strict_types=1);

namespace App\JabaliTerminal\Pages;

use App\JabaliTerminal\Http\PreventFramingMiddleware;
use BackedEnum;
use Filament\Pages\Page;
use UnitEnum;

/**
 * Browser root terminal page.
 *
 * Security posture (see docs/SECURITY.md):
 *  - canAccess() hard-fails for non-admins BEFORE mount runs.
 *  - Re-auth (password + 2FA) is performed by a dedicated HTTP route,
 *    POST /jabali-admin/terminal/session, handled by
 *    TerminalSessionController — this page only renders the modal and
 *    drives the xterm.js bundle.
 *  - The token returned by that route lives only in JavaScript memory —
 *    the Blade view never renders it into the DOM and the route never
 *    persists it.
 *  - SEC-REV-8: PreventFramingMiddleware pins X-Frame-Options: DENY and
 *    CSP frame-ancestors 'none' on every response.
 */
class Terminal extends Page
{
    protected static string|BackedEnum|null $navigationIcon = 'heroicon-o-command-line';

    // Filament 4 requires the property type to match the parent exactly
    // (invariant for typed properties): UnitEnum|string|null. A plain
    // ?string declaration would fatal at class load.
    protected static UnitEnum|string|null $navigationGroup = 'Tools';

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

    /**
     * True when the current admin has Fortify 2FA configured on their
     * account. The re-auth modal hides the 2FA input when this is false;
     * the controller mirrors the check server-side so a hand-crafted
     * request cannot bypass a configured second factor.
     */
    public bool $requiresTwoFactor = false;

    public function mount(): void
    {
        abort_unless(static::canAccess(), 403);
        $user = auth()->user();
        $this->requiresTwoFactor = $user !== null && ! empty($user->two_factor_secret);
    }
}
