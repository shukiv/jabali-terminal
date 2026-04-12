<x-filament-panels::page>
    <div class="space-y-4">
        <div class="flex items-center justify-between">
            <div class="text-sm text-gray-500">
                {{ __('Last 100 sessions. Transcripts are sealed with HMAC on close.') }}
            </div>
            <button
                type="button"
                wire:click="refresh"
                class="rounded bg-cyan-600 px-3 py-1 text-sm font-medium text-white hover:bg-cyan-500"
            >
                {{ __('Refresh') }}
            </button>
        </div>

        <div class="overflow-hidden rounded-lg border border-gray-200 bg-white shadow-sm dark:border-gray-800 dark:bg-gray-900">
            <table class="min-w-full divide-y divide-gray-200 dark:divide-gray-800 text-sm">
                <thead class="bg-gray-50 dark:bg-gray-800">
                    <tr>
                        <th class="px-4 py-2 text-left font-medium">{{ __('Date') }}</th>
                        <th class="px-4 py-2 text-left font-medium">{{ __('Admin') }}</th>
                        <th class="px-4 py-2 text-left font-medium">{{ __('Session') }}</th>
                        <th class="px-4 py-2 text-right font-medium">{{ __('Size') }}</th>
                        <th class="px-4 py-2 text-left font-medium">{{ __('Sealed') }}</th>
                        <th class="px-4 py-2 text-right font-medium"></th>
                    </tr>
                </thead>
                <tbody class="divide-y divide-gray-100 dark:divide-gray-800">
                    @forelse ($sessions as $session)
                        <tr>
                            <td class="px-4 py-2 font-mono text-xs">{{ $session['date'] ?? '' }}</td>
                            <td class="px-4 py-2">{{ $session['admin'] ?? '' }}</td>
                            <td class="px-4 py-2 font-mono text-xs">{{ $session['session_id'] ?? '' }}</td>
                            <td class="px-4 py-2 text-right">{{ number_format((int) ($session['size_bytes'] ?? 0)) }} B</td>
                            <td class="px-4 py-2">
                                @if ($session['sealed'] ?? false)
                                    <span class="rounded bg-green-100 px-2 py-0.5 text-xs text-green-800 dark:bg-green-900 dark:text-green-200">{{ __('sealed') }}</span>
                                @else
                                    <span class="rounded bg-yellow-100 px-2 py-0.5 text-xs text-yellow-800 dark:bg-yellow-900 dark:text-yellow-200">{{ __('unsealed') }}</span>
                                @endif
                            </td>
                            <td class="px-4 py-2 text-right">
                                <button
                                    type="button"
                                    wire:click="viewTranscript(@js($session['name'] ?? ''))"
                                    class="text-cyan-600 hover:underline dark:text-cyan-400"
                                >
                                    {{ __('View') }}
                                </button>
                            </td>
                        </tr>
                    @empty
                        <tr>
                            <td colspan="6" class="px-4 py-6 text-center text-gray-500">
                                {{ __('No sessions recorded yet.') }}
                            </td>
                        </tr>
                    @endforelse
                </tbody>
            </table>
        </div>

        @if ($transcript !== null)
            <div class="rounded-lg border border-gray-200 bg-gray-950 p-4 shadow-sm dark:border-gray-800">
                <div class="mb-2 flex items-center justify-between text-sm">
                    <span class="font-mono text-xs text-gray-400">{{ $openName }}</span>
                    <button
                        type="button"
                        wire:click="closeTranscript"
                        class="rounded bg-gray-700 px-3 py-1 text-xs text-white hover:bg-gray-600"
                    >
                        {{ __('Close') }}
                    </button>
                </div>
                {{-- Plain <pre>: we never {!! !!} the transcript; Blade auto-escapes so
                     arbitrary bytes written by the daemon cannot inject HTML. --}}
                <pre class="max-h-[60vh] overflow-auto whitespace-pre-wrap break-words text-xs text-gray-200">{{ $transcript }}</pre>
            </div>
        @endif
    </div>
</x-filament-panels::page>
