<?php

declare(strict_types=1);

namespace App\JabaliTerminal\Pages;

use App\JabaliTerminal\Http\PreventFramingMiddleware;
use App\JabaliTerminal\JabaliTerminalClient;
use BackedEnum;
use Filament\Pages\Page;
use UnitEnum;

/**
 * Read-only index of past root-shell sessions.
 *
 * Security:
 *  - canAccess() blocks non-admins (same policy as the Terminal page).
 *  - Transcript bodies are fetched lazily via viewTranscript() through the
 *    unix socket. The daemon enforces a 1 MiB cap + path whitelist; this
 *    page only renders what it receives as plain text (never as HTML).
 *  - No mutation paths exist on this page — transcripts cannot be deleted
 *    or edited from the panel. Use the CLI or logrotate for that.
 */
class Sessions extends Page
{
    protected static string|BackedEnum|null $navigationIcon = 'heroicon-o-clock';

    // Terminal Sessions sits immediately below Root Terminal (sort 11),
    // same top-level section as Services.
    protected static UnitEnum|string|null $navigationGroup = null;

    protected static ?int $navigationSort = 12;

    protected static ?string $slug = 'terminal/sessions';

    protected static ?string $title = 'Terminal Sessions';

    protected string $view = 'jabali-terminal::sessions';

    /** @var string|array<string> */
    protected static string|array $routeMiddleware = [PreventFramingMiddleware::class];

    /**
     * The current list of sessions, refreshed on mount and on refresh().
     *
     * @var array<int, array<string, mixed>>
     */
    public array $sessions = [];

    /** Active transcript (null if none open), plain-text only. */
    public ?string $transcript = null;

    public ?string $openName = null;

    public static function canAccess(): bool
    {
        $user = auth()->user();

        return $user !== null && method_exists($user, 'isAdmin') && $user->isAdmin();
    }

    public function mount(): void
    {
        abort_unless(static::canAccess(), 403);
        $this->refresh();
    }

    public function refresh(): void
    {
        $this->sessions = app(JabaliTerminalClient::class)->listSessions();
    }

    public function viewTranscript(string $name): void
    {
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
