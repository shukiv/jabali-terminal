<x-filament-panels::page>
    <div class="flex flex-col gap-4">
        <x-filament::section>
            <div class="flex items-center justify-between">
                <p class="text-sm text-gray-500 dark:text-gray-400">
                    {{ __('Last 100 sessions. Transcripts are sealed with HMAC on close.') }}
                </p>
                <x-filament::button
                    color="gray"
                    size="sm"
                    icon="heroicon-o-arrow-path"
                    wire:click="refresh"
                >
                    {{ __('Refresh') }}
                </x-filament::button>
            </div>
        </x-filament::section>

        <x-filament::section>
            @if (empty($sessions))
                <div class="flex flex-col items-center justify-center gap-2 py-10 text-center">
                    <x-filament::icon
                        icon="heroicon-o-clock"
                        class="h-8 w-8 text-gray-400"
                    />
                    <p class="text-sm text-gray-500 dark:text-gray-400">
                        {{ __('No sessions recorded yet.') }}
                    </p>
                </div>
            @else
                <div class="overflow-x-auto">
                    <table class="w-full text-start text-sm">
                        <thead>
                            <tr class="border-b border-gray-200 dark:border-white/10">
                                <th class="px-3 py-2 text-start font-medium text-gray-500 dark:text-gray-300">{{ __('Date') }}</th>
                                <th class="px-3 py-2 text-start font-medium text-gray-500 dark:text-gray-300">{{ __('Admin') }}</th>
                                <th class="px-3 py-2 text-start font-medium text-gray-500 dark:text-gray-300">{{ __('Session') }}</th>
                                <th class="px-3 py-2 text-end font-medium text-gray-500 dark:text-gray-300">{{ __('Size') }}</th>
                                <th class="px-3 py-2 text-start font-medium text-gray-500 dark:text-gray-300">{{ __('Sealed') }}</th>
                                <th class="px-3 py-2 text-end font-medium text-gray-500 dark:text-gray-300"></th>
                            </tr>
                        </thead>
                        <tbody class="divide-y divide-gray-200 dark:divide-white/5">
                            @foreach ($sessions as $session)
                                <tr>
                                    <td class="px-3 py-2 font-mono text-xs">{{ $session['date'] ?? '' }}</td>
                                    <td class="px-3 py-2">{{ $session['admin'] ?? '' }}</td>
                                    <td class="px-3 py-2 font-mono text-xs">{{ $session['session_id'] ?? '' }}</td>
                                    <td class="px-3 py-2 text-end tabular-nums">{{ number_format((int) ($session['size_bytes'] ?? 0)) }} B</td>
                                    <td class="px-3 py-2">
                                        @if ($session['sealed'] ?? false)
                                            <x-filament::badge color="success" icon="heroicon-o-lock-closed" size="sm">
                                                {{ __('sealed') }}
                                            </x-filament::badge>
                                        @else
                                            <x-filament::badge color="warning" icon="heroicon-o-lock-open" size="sm">
                                                {{ __('unsealed') }}
                                            </x-filament::badge>
                                        @endif
                                    </td>
                                    <td class="px-3 py-2 text-end">
                                        <x-filament::link
                                            tag="button"
                                            wire:click="viewTranscript(@js($session['name'] ?? ''))"
                                            icon="heroicon-o-eye"
                                        >
                                            {{ __('View') }}
                                        </x-filament::link>
                                    </td>
                                </tr>
                            @endforeach
                        </tbody>
                    </table>
                </div>
            @endif
        </x-filament::section>

        @if ($transcript !== null)
            <x-filament::section
                :heading="$openName"
                icon="heroicon-o-document-text"
            >
                <x-slot name="headerEnd">
                    <x-filament::button
                        color="gray"
                        size="sm"
                        icon="heroicon-o-x-mark"
                        wire:click="closeTranscript"
                    >
                        {{ __('Close') }}
                    </x-filament::button>
                </x-slot>
                {{-- Plain <pre>: we never {!! !!} the transcript; Blade auto-escapes so
                     arbitrary bytes written by the daemon cannot inject HTML. --}}
                <pre class="max-h-[60vh] overflow-auto whitespace-pre-wrap break-words rounded-lg bg-gray-950 p-4 font-mono text-xs text-gray-200">{{ $transcript }}</pre>
            </x-filament::section>
        @endif
    </div>
</x-filament-panels::page>
