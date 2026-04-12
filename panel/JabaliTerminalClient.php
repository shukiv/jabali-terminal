<?php

declare(strict_types=1);

namespace App\JabaliTerminal;

use Illuminate\Support\Facades\Http;
use Illuminate\Support\Facades\Log;

/**
 * HTTP client for the jabali-terminal daemon over its unix socket.
 *
 * Never talks to a TCP port — if the socket is missing, the daemon is
 * considered unavailable. The request body is HMAC-signed with the shared
 * secret from /etc/jabali-terminal/jabali-terminal.conf so that even if the
 * socket permissions regress, an unprivileged writer cannot mint tokens.
 */
class JabaliTerminalClient
{
    protected string $baseUrl = 'http://localhost';

    protected ?string $socketPath = null;

    protected ?string $hmacSecretHex = null;

    private static ?self $instance = null;

    public static function getInstance(): self
    {
        if (self::$instance === null) {
            self::$instance = new self;
        }

        return self::$instance;
    }

    public function __construct()
    {
        $this->loadConfig();
    }

    /**
     * True if the daemon is reachable and healthy.
     */
    public function isAvailable(): bool
    {
        if (! $this->socketPath || ! file_exists($this->socketPath)) {
            return false;
        }

        try {
            $response = $this->request()->timeout(3)
                ->get($this->baseUrl.'/health');

            return $response->successful();
        } catch (\Throwable) {
            return false;
        }
    }

    /**
     * Mint a short-lived, single-use session token for an admin.
     *
     * Returns ['ws_url' => string, 'token' => string, 'expires_at' => int]
     * or null on failure.
     *
     * The token MUST be kept in memory only on the client side (SEC-REV-2).
     * Do NOT log, do NOT render into HTML, do NOT persist.
     */
    public function requestSession(int $adminUserId, string $ip): ?array
    {
        if (! $this->socketPath || ! $this->hmacSecretHex) {
            Log::error('JabaliTerminal: daemon not configured (socket or HMAC missing)');

            return null;
        }

        $nonce = bin2hex(random_bytes(32));
        $issuedAt = time();

        // Signature binds every field — server re-computes and compares in constant time.
        // Canonical form: "admin_id|ip|nonce|issued_at"
        $payload = [
            'admin_id' => $adminUserId,
            'ip' => $ip,
            'nonce' => $nonce,
            'issued_at' => $issuedAt,
        ];
        $signingString = $adminUserId.'|'.$ip.'|'.$nonce.'|'.$issuedAt;
        $payload['hmac'] = hash_hmac('sha256', $signingString, hex2bin($this->hmacSecretHex));

        try {
            $response = $this->request()
                ->timeout(5)
                ->post($this->baseUrl.'/api/v1/session', $payload);

            if (! $response->successful()) {
                Log::error('JabaliTerminal: session request failed with '.$response->status());

                return null;
            }

            $data = $response->json();

            if (! is_array($data)
                || ! isset($data['token'], $data['ws_url'], $data['expires_at'])) {
                Log::error('JabaliTerminal: malformed session response');

                return null;
            }

            return $data;
        } catch (\Throwable $e) {
            Log::error('JabaliTerminal: daemon unreachable: '.$e->getMessage());

            return null;
        }
    }

    protected function request(): \Illuminate\Http\Client\PendingRequest
    {
        $request = Http::withHeaders(['Accept' => 'application/json']);
        if ($this->socketPath) {
            $request = $request->withOptions([
                'curl' => [CURLOPT_UNIX_SOCKET_PATH => $this->socketPath],
            ]);
        }

        return $request;
    }

    protected function loadConfig(): void
    {
        $configFile = '/etc/jabali-terminal/jabali-terminal.conf';
        if (! is_readable($configFile)) {
            return;
        }

        $content = file_get_contents($configFile);
        if ($content === false) {
            return;
        }

        if (preg_match('/^socket_path="([^"]*)"$/m', $content, $m)) {
            $this->socketPath = $m[1] !== '' ? $m[1] : null;
        } else {
            $this->socketPath = '/run/jabali-terminal/jabali-terminal.sock';
        }

        if (preg_match('/^hmac_secret="([^"]*)"$/m', $content, $m)) {
            // Must be valid hex; a blank or malformed value disables the client.
            $hex = $m[1];
            if ($hex !== '' && ctype_xdigit($hex) && strlen($hex) >= 64) {
                $this->hmacSecretHex = $hex;
            }
        }
    }
}
