<?php

declare(strict_types=1);

namespace App\JabaliTerminal\Pages;

use App\JabaliTerminal\Http\PreventFramingMiddleware;
use App\JabaliTerminal\JabaliTerminalClient;
use BackedEnum;
use Filament\Pages\Page;
use UnitEnum;

/**
 * Browser root terminal + session transcript browser.
 *
 * The page has two tabs:
 *  - Terminal: re-auth → live xterm.js PTY (Alpine-driven, WS stays alive
 *    across tab switches because Alpine only toggles display:none).
 *  - Sessions: read-only index of HMAC-sealed transcripts (Livewire).
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
 *  - Session transcripts are fetched lazily via viewTranscript() through
 *    the unix socket. The daemon enforces a 1 MiB cap + path whitelist;
 *    this page only renders what it receives as plain text.
 */
class Terminal extends Page
{
    protected static string|BackedEnum|null $navigationIcon = 'heroicon-o-command-line';

    // Filament 4 requires the property type to match the parent exactly
    // (invariant for typed properties): UnitEnum|string|null. A plain
    // ?string declaration would fatal at class load.
    //
    // Root Terminal lives in the main navigation right after "Services"
    // (Services has navigationSort 10). No custom navigationGroup — stays
    // in the default top-level section so operators don't have to scroll
    // to the "Tools" group for a frequently-used action.
    protected static UnitEnum|string|null $navigationGroup = null;

    protected static ?int $navigationSort = 11;

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

    /**
     * Sealed/unsealed session transcripts, loaded on mount and on refresh.
     *
     * @var array<int, array<string, mixed>>
     */
    public array $sessions = [];

    /** Active transcript body (plain text only, never rendered as HTML). */
    public ?string $transcript = null;

    /** File name of the currently open transcript. */
    public ?string $openName = null;

    public function mount(): void
    {
        abort_unless(static::canAccess(), 403);
        $user = auth()->user();
        $this->requiresTwoFactor = $user !== null && ! empty($user->two_factor_secret);

        // Session list is cheap (directory listing over the unix socket);
        // fetch once so the Sessions tab is populated on first render
        // without a Livewire round-trip.
        $this->refreshSessions();
    }

    public function refreshSessions(): void
    {
        // Defense-in-depth: Filament's panel middleware already enforces
        // auth:admin on Livewire XHRs, but canAccess() (isAdmin()) is not
        // re-run automatically. Mirror the mount() gate so a session whose
        // admin role was revoked mid-flight can't still read transcripts.
        abort_unless(static::canAccess(), 403);
        $this->sessions = app(JabaliTerminalClient::class)->listSessions();
    }

    public function viewTranscript(string $name): void
    {
        abort_unless(static::canAccess(), 403);
        // Re-validate on every call. The client + daemon both validate too,
        // but the Livewire property is attacker-controlled.
        if (! preg_match('/^[0-9A-Za-z._-]{1,128}\.log$/', $name)) {
            return;
        }

        $this->openName = $name;
        $this->transcript = app(JabaliTerminalClient::class)->getTranscript($name);
    }

    public function closeTranscript(): void
    {
        $this->openName = null;
        $this->transcript = null;
    }
}
