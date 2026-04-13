<?php

declare(strict_types=1);

namespace App\JabaliTerminal\Pages;

use App\JabaliTerminal\Http\PreventFramingMiddleware;
use App\JabaliTerminal\JabaliTerminalClient;
use BackedEnum;
use Filament\Pages\Page;
use Illuminate\Support\Facades\RateLimiter;
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
        $this->throttleTranscriptCall('refresh');
        $this->sessions = app(JabaliTerminalClient::class)->listSessions();
    }

    /**
     * Open the transcript for a session by its index into $this->sessions.
     * The blade uses this (not viewTranscript) because passing a numeric
     * index through `wire:click="method(N)"` parses cleanly in Livewire 4
     * regardless of surrounding component chrome — no string escaping,
     * no @js() directives, no Filament component attribute-bag oddities.
     * The string-based viewTranscript() is still here for the feature
     * test suite + CLI / direct Livewire calls.
     */
    public function viewTranscriptAt(int $index): void
    {
        abort_unless(static::canAccess(), 403);
        $this->throttleTranscriptCall('view');
        $name = (string) ($this->sessions[$index]['name'] ?? '');
        $this->loadTranscript($name);
    }

    public function viewTranscript(string $name): void
    {
        abort_unless(static::canAccess(), 403);
        $this->throttleTranscriptCall('view');
        $this->loadTranscript($name);
    }

    private function loadTranscript(string $name): void
    {
        // Re-validate on every call. The client + daemon both validate too,
        // but the Livewire property is attacker-controlled. Mirror the
        // daemon's substring check on ".." (belt-and-suspenders — the
        // charset excludes / already, but two dots in a row trigger
        // path-traversal scanners and don't correspond to any legitimate
        // filename the daemon produces).
        if ($name === '' || str_contains($name, '..') || ! preg_match('/^[0-9A-Za-z._-]{1,128}\.log$/', $name)) {
            return;
        }

        $this->openName = $name;
        $raw = app(JabaliTerminalClient::class)->getTranscript($name);
        // The raw log is what the audit HMAC-sig was computed over and stays
        // byte-accurate on disk — but what the browser shows doesn't have to
        // be raw bytes interleaved with PTY control codes. renderTranscript()
        // strips ANSI escape sequences and coalesces consecutive same-stream
        // writes into single paragraphs so "dir<enter>" reads as one input
        // line instead of eight per-keystroke [STDIN]/[STDOUT] pairs.
        $this->transcript = $raw !== null ? static::renderTranscript($raw) : null;
    }

    /**
     * Clean a raw audit transcript for browser display.
     *
     * Does NOT modify anything on disk — the daemon-sealed log stays bit-exact
     * for forensic re-verification. This function only transforms the copy
     * that rides back through the Livewire `$transcript` property. Two passes:
     *   1. ANSI escape sequences (CSI, OSC, charset designators, bare ESC)
     *      are stripped so "[?2004h", "[K", colour codes etc. don't show as
     *      literal text in the <pre>.
     *   2. Per-write [STDIN]/[STDOUT] labels are coalesced: consecutive writes
     *      from the same stream collapse into one labelled block. A typed
     *      "dir" used to show as 8 labelled lines (4 stdin keystrokes + 4
     *      stdout echoes); it now shows as "[STDIN] dir\n[STDOUT] dir".
     */
    public static function renderTranscript(string $raw): string
    {
        // Pass 1 — strip ANSI / terminal control noise.
        //   CSI: ESC [ params intermediates final
        $clean = (string) preg_replace('/\x1b\[[0-?]*[ -\/]*[@-~]/', '', $raw);
        //   OSC: ESC ] ... BEL  or  ESC ] ... ESC \
        $clean = (string) preg_replace('/\x1b\].*?(?:\x07|\x1b\\\\)/s', '', $clean);
        //   Charset / 2-char escapes: ESC ( B, ESC ) 0, ESC # 8, ...
        $clean = (string) preg_replace('/\x1b[()#][@-~]/', '', $clean);
        //   Any remaining bare ESC sequences.
        $clean = (string) preg_replace('/\x1b[@-Z\\\\-_]/', '', $clean);
        //   Lone CR (terminal overwrite) — keep CRLF, drop standalone \r.
        $clean = (string) preg_replace('/\r(?!\n)/', '', $clean);

        // Pass 2 — coalesce consecutive same-stream writes.
        //
        // Audit log format (from daemon/audit.py):
        //   # Session start: ...
        //   [STDOUT] <bytes that may span multiple lines>
        //   [STDIN] <bytes>
        //   # Session end: ...
        //
        // A label only appears at the start of a line that begins with
        // "[STDIN] " or "[STDOUT] ". Lines without a label are continuations
        // of the previous labelled chunk.
        $lines = explode("\n", $clean);
        $out = [];
        $currentLabel = null;
        $currentBuf = [];

        $flush = static function () use (&$out, &$currentLabel, &$currentBuf): void {
            if ($currentLabel === null) {
                return;
            }
            // Trim both leading and trailing empty segments. A pure-ANSI
            // chunk (e.g. "[STDOUT] \x1b[?2004l") leaves an empty first
            // segment after pass 1; its continuation bytes on the next
            // line are the real content and should be the first visible
            // thing after the label.
            $content = trim(implode("\n", $currentBuf), "\n");
            if ($content === '') {
                $currentBuf = [];
                $currentLabel = null;

                return;
            }
            $out[] = $currentLabel.' '.$content;
            $currentBuf = [];
            $currentLabel = null;
        };

        foreach ($lines as $line) {
            if (str_starts_with($line, '# ')) {
                $flush();
                $out[] = $line;

                continue;
            }
            if (str_starts_with($line, '[STDIN] ') || str_starts_with($line, '[STDOUT] ')) {
                $label = str_starts_with($line, '[STDIN] ') ? '[STDIN]' : '[STDOUT]';
                $rest = substr($line, strlen($label) + 1);
                if ($label === $currentLabel) {
                    $currentBuf[] = $rest;
                } else {
                    $flush();
                    $currentLabel = $label;
                    $currentBuf = [$rest];
                }

                continue;
            }
            // Continuation of the current labelled block (no label prefix).
            if ($currentLabel !== null) {
                $currentBuf[] = $line;
            } else {
                // Orphan line before any label — pass through.
                $out[] = $line;
            }
        }
        $flush();

        return implode("\n", $out);
    }

    /**
     * Rate-limit Livewire methods that hit the daemon — 60/min per admin+ip.
     * The daemon has its own timeouts and caps, but a compromised admin
     * session shouldn't be able to flood the unix socket either; this keeps
     * the surface bounded the same way the mint route is bounded (3/min).
     * 60/min is loose enough for a legitimate admin scanning transcripts.
     */
    private function throttleTranscriptCall(string $bucket): void
    {
        $key = 'jt-transcript:'.$bucket.':'.auth()->id().':'.request()->ip();
        if (RateLimiter::tooManyAttempts($key, 60)) {
            abort(429, 'too many transcript requests, wait a minute');
        }
        RateLimiter::hit($key, 60);
    }

    public function closeTranscript(): void
    {
        $this->openName = null;
        $this->transcript = null;
    }
}
