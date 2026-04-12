<x-filament-panels::page>
    {{-- Jabali Terminal page. See docs/SECURITY.md for the auth flow this view implements. --}}
    {{--
        xterm.js is bundled by the parent panel via Vite (resources/js/jabali-terminal.js).
        The module is imported on demand so other panel pages don't pay the cost.
        CSP forbids CDN script loads (SEC-REV-8 reinforcement) — do NOT switch to a CDN.
    --}}
    @vite(['resources/css/jabali-terminal.css', 'resources/js/jabali-terminal.js'])

    <div
        id="jt-root"
        x-data="jabaliTerminal()"
        x-init="init()"
        wire:ignore
        class="flex h-[70vh] flex-col gap-3 rounded-xl bg-gray-950 p-3 text-gray-200 shadow-lg"
    >
        {{-- Re-auth modal --}}
        <div
            x-show="stage === 'auth'"
            x-cloak
            class="flex flex-1 items-center justify-center"
        >
            <form
                @submit.prevent="submitAuth()"
                class="w-full max-w-md space-y-3 rounded-lg border border-gray-800 bg-gray-900 p-5"
            >
                <h2 class="text-base font-semibold text-white">
                    {{ __('Re-authenticate to open a root shell') }}
                </h2>
                <p class="text-xs text-gray-400">
                    {{ __('A fresh password and 2FA code are required every time. The shell runs as root.') }}
                </p>
                <input
                    type="password"
                    x-model="password"
                    :disabled="busy"
                    autocomplete="current-password"
                    placeholder="{{ __('Password') }}"
                    class="w-full rounded border border-gray-700 bg-gray-950 px-3 py-2 text-sm text-white focus:border-cyan-500 focus:outline-none"
                    required
                />
                <input
                    type="text"
                    inputmode="numeric"
                    pattern="[0-9]*"
                    maxlength="10"
                    x-model="twoFactorCode"
                    :disabled="busy"
                    autocomplete="one-time-code"
                    placeholder="{{ __('2FA code') }}"
                    class="w-full rounded border border-gray-700 bg-gray-950 px-3 py-2 text-sm text-white focus:border-cyan-500 focus:outline-none"
                    required
                />
                <template x-if="error">
                    <p class="rounded bg-red-900/50 px-3 py-2 text-xs text-red-200" x-text="error"></p>
                </template>
                <button
                    type="submit"
                    :disabled="busy || password.length === 0 || twoFactorCode.length === 0"
                    class="w-full rounded bg-cyan-600 px-3 py-2 text-sm font-medium text-white hover:bg-cyan-500 disabled:opacity-50"
                >
                    <span x-show="!busy">{{ __('Open terminal') }}</span>
                    <span x-show="busy">{{ __('Opening…') }}</span>
                </button>
            </form>
        </div>

        {{-- Live terminal --}}
        <div x-show="stage === 'live'" x-cloak class="flex flex-1 flex-col gap-2">
            <div class="flex items-center justify-between rounded bg-gray-900 px-3 py-2 text-xs">
                <span>
                    <span class="inline-block h-2 w-2 rounded-full" :class="connected ? 'bg-green-500' : 'bg-yellow-500'"></span>
                    <span x-text="connected ? '{{ __('Connected') }}' : '{{ __('Connecting…') }}'"></span>
                </span>
                <button
                    type="button"
                    @click="endSession()"
                    class="rounded bg-red-600 px-3 py-1 font-medium text-white hover:bg-red-500"
                >
                    {{ __('End session') }}
                </button>
            </div>
            <div id="jt-xterm" class="flex-1 overflow-hidden rounded bg-black"></div>
            <template x-if="warning">
                <p class="rounded bg-yellow-900/60 px-3 py-2 text-xs text-yellow-200" x-text="warning"></p>
            </template>
        </div>

        {{-- Closed state --}}
        <div x-show="stage === 'closed'" x-cloak class="flex flex-1 flex-col items-center justify-center gap-3 text-sm text-gray-400">
            <p x-text="closeReason || '{{ __('Session closed') }}'"></p>
            <button type="button" @click="resetToAuth()" class="rounded bg-cyan-600 px-3 py-1 text-sm text-white hover:bg-cyan-500">
                {{ __('Open another session') }}
            </button>
        </div>
    </div>

    {{--
        The Alpine factory below is intentionally small — all heavy lifting
        (xterm.js, Web Crypto HMAC, WebSocket) lives in the Vite bundle under
        resources/js/jabali-terminal.js so it is audited alongside the rest
        of the panel's JS.

        Contract with the bundle:
          window.jabaliTerminalBundle = {
              createTerminal(containerEl, { onData, onResize }): { writeBytes, fit, dispose },
              hmacHex(keyBytes, messageBytes): Promise<string>,  // HMAC-SHA256 via Web Crypto
              base64urlDecode(s): Uint8Array,
          };
    --}}
    <script>
        function jabaliTerminal() {
            // SEC-REV-2: token lives in this closure variable only. It is never
            // rendered into the DOM and is overwritten with null as soon as the
            // WS auth frame has been sent.
            let token = null;
            let ws = null;
            let term = null;

            return {
                stage: 'auth',
                password: '',
                twoFactorCode: '',
                busy: false,
                error: '',
                warning: '',
                connected: false,
                closeReason: '',

                async init() {
                    // Nothing to pre-load; the bundle is loaded by @vite above.
                },

                async submitAuth() {
                    this.error = '';
                    this.busy = true;
                    try {
                        // Dedicated route (Step 6) — never Livewire — so the
                        // response JSON never rides through an HTML render.
                        const csrf = document.querySelector('meta[name="csrf-token"]');
                        const response = await fetch('{{ route('jabali-terminal.session') }}', {
                            method: 'POST',
                            credentials: 'same-origin',
                            headers: {
                                'Content-Type': 'application/json',
                                'Accept': 'application/json',
                                'X-CSRF-TOKEN': csrf ? csrf.getAttribute('content') : '',
                                'X-Requested-With': 'XMLHttpRequest',
                            },
                            body: JSON.stringify({
                                password: this.password,
                                two_factor_code: this.twoFactorCode,
                            }),
                        });
                        // Scrub secrets from local state regardless of outcome.
                        this.password = '';
                        this.twoFactorCode = '';

                        if (response.status === 429) {
                            this.error = 'too many attempts, wait a minute';
                            return;
                        }
                        if (!response.ok) {
                            // Generic message — do not differentiate 422 vs 403
                            // vs 502 to the user; status just tells us whether
                            // to let them retry now or show "try later".
                            this.error = (response.status >= 500)
                                ? 'daemon unavailable'
                                : 'invalid credentials';
                            return;
                        }

                        const result = await response.json();
                        if (!result || !result.token || !result.ws_url) {
                            this.error = 'session mint failed';
                            return;
                        }
                        token = result.token;
                        await this.openWebSocket(result.ws_url);
                    } catch (e) {
                        this.error = 'authentication failed';
                    } finally {
                        this.busy = false;
                    }
                },

                async openWebSocket(wsUrl) {
                    const bundle = window.jabaliTerminalBundle;
                    if (!bundle) {
                        this.error = 'terminal bundle missing';
                        return;
                    }

                    this.stage = 'live';
                    this.connected = false;

                    // Extract the 32B nonce at bytes 40..72 of the 104B raw token.
                    const rawToken = bundle.base64urlDecode(token);
                    if (rawToken.length !== 104) {
                        this.stage = 'closed';
                        this.closeReason = 'malformed token';
                        return;
                    }
                    const tokenNonce = rawToken.slice(40, 72);

                    ws = new WebSocket(wsUrl);
                    ws.binaryType = 'arraybuffer';

                    ws.addEventListener('message', async (evt) => {
                        // First message must be the challenge (SEC-REV-2).
                        if (term === null) {
                            let msg;
                            try {
                                msg = JSON.parse(typeof evt.data === 'string' ? evt.data : new TextDecoder().decode(evt.data));
                            } catch {
                                ws.close();
                                return;
                            }
                            if (msg.type !== 'challenge' || typeof msg.nonce !== 'string') {
                                ws.close();
                                return;
                            }
                            // Compute HMAC-SHA256(token_nonce, challenge_nonce_bytes) via Web Crypto.
                            const challengeBytes = hexToBytes(msg.nonce);
                            const nonceResponse = await bundle.hmacHex(tokenNonce, challengeBytes);
                            const authToken = token;
                            token = null; // SEC-REV-2: drop the token from memory immediately.
                            ws.send(JSON.stringify({
                                type: 'auth',
                                token: authToken,
                                nonce_response: nonceResponse,
                            }));
                            this.connected = true;
                            this.mountTerminal();
                            return;
                        }

                        // Post-auth: PTY bytes from daemon.
                        if (typeof evt.data === 'string') {
                            term.writeBytes(new TextEncoder().encode(evt.data));
                        } else {
                            term.writeBytes(new Uint8Array(evt.data));
                        }
                    });

                    ws.addEventListener('close', (evt) => {
                        this.connected = false;
                        this.stage = 'closed';
                        this.closeReason = evt.reason || 'session closed';
                        if (term) {
                            term.dispose();
                            term = null;
                        }
                    });

                    ws.addEventListener('error', () => {
                        // Don't leak details — close handler will flip UI state.
                    });
                },

                mountTerminal() {
                    const bundle = window.jabaliTerminalBundle;
                    const container = document.getElementById('jt-xterm');
                    if (!container) {
                        return;
                    }
                    term = bundle.createTerminal(container, {
                        onData: (bytes) => {
                            if (ws && ws.readyState === WebSocket.OPEN) {
                                ws.send(bytes);
                            }
                        },
                        onResize: ({ cols, rows }) => {
                            if (ws && ws.readyState === WebSocket.OPEN) {
                                ws.send(JSON.stringify({ type: 'resize', cols, rows }));
                            }
                        },
                    });
                    term.fit();

                    // 4KB paste cap (SEC-REV-2 paste defence).
                    container.addEventListener('paste', (ev) => {
                        const data = ev.clipboardData && ev.clipboardData.getData('text');
                        if (data && data.length > 4096) {
                            ev.preventDefault();
                            this.warning = 'paste larger than 4KB was blocked';
                            setTimeout(() => { this.warning = ''; }, 4000);
                        }
                    }, true);
                },

                endSession() {
                    if (ws && ws.readyState !== WebSocket.CLOSED) {
                        ws.close(1000, 'user ended session');
                    }
                },

                resetToAuth() {
                    this.stage = 'auth';
                    this.error = '';
                    this.warning = '';
                    this.closeReason = '';
                },
            };

            function hexToBytes(hex) {
                const out = new Uint8Array(hex.length / 2);
                for (let i = 0; i < out.length; i++) {
                    out[i] = parseInt(hex.substr(i * 2, 2), 16);
                }
                return out;
            }
        }
    </script>
</x-filament-panels::page>
