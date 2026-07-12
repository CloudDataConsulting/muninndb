<?php

declare(strict_types=1);

require_once __DIR__ . '/../src/Types/Types.php';

use MuninnDB\Types\StatsResponse;

function assertSameValue(mixed $expected, mixed $actual, string $message): void
{
    if ($expected !== $actual) {
        fwrite(STDERR, "$message: expected " . var_export($expected, true)
            . ', got ' . var_export($actual, true) . PHP_EOL);
        exit(1);
    }
}

$current = StatsResponse::fromArray([
    'engram_count' => 42,
    'vault_count' => 1,
    'index_size' => 0,
    'storage_bytes' => 0,
    'stats_scope' => 'vault',
    'storage_bytes_available' => false,
    'index_size_available' => false,
    'coherence' => [
        'client-a' => [
            'score' => 0.9,
            'orphan_ratio' => 0.1,
            'contradiction_density' => 0.02,
            'duplication_pressure' => 0.03,
            'temporal_variance' => 0.04,
            'total_engrams' => 42,
        ],
    ],
]);

assertSameValue(42, $current->engramCount, 'current engram count');
assertSameValue(42, $current->totalEngrams, 'legacy engram alias');
assertSameValue('vault', $current->statsScope, 'current stats scope');
assertSameValue(false, $current->storageBytesAvailable, 'storage availability');
assertSameValue(0, $current->totalLinks, 'legacy missing links keep zero default');
assertSameValue(1, $current->totalVaults, 'legacy vault alias');
assertSameValue(42, $current->coherenceByVault['client-a']->totalEngrams, 'coherence map');
assertSameValue(0.9, $current->coherence?->score, 'legacy coherence alias');

$legacy = StatsResponse::fromArray([
    'total_engrams' => 7,
    'total_vaults' => 3,
    'total_links' => 5,
    'coherence' => ['score' => 0.5, 'contradictions' => 2],
]);

assertSameValue(7, $legacy->engramCount, 'legacy engram fallback');
assertSameValue(3, $legacy->vaultCount, 'legacy vault fallback');
assertSameValue('unknown', $legacy->statsScope, 'legacy scope is unknown');
assertSameValue(false, $legacy->storageBytesAvailable, 'legacy sizes are unavailable');
assertSameValue(5, $legacy->totalLinks, 'legacy links preserved');
assertSameValue(2, $legacy->coherence?->contradictions, 'legacy coherence preserved');

$legacyMissingVaults = StatsResponse::fromArray(['total_engrams' => 2]);
assertSameValue(null, $legacyMissingVaults->totalVaults, 'missing legacy vault count stays null');
assertSameValue(null, $legacyMissingVaults->vaultCount, 'normalized missing vault count stays null');

$constructed = new StatsResponse(
    totalEngrams: 9,
    totalLinks: 4,
    totalVaults: null,
    coherence: new \MuninnDB\Types\CoherenceResult(0.5, 3),
);
assertSameValue(9, $constructed->engramCount, 'legacy named constructor engram alias');
assertSameValue(null, $constructed->vaultCount, 'legacy named constructor nullable vaults');
assertSameValue(3, $constructed->coherence?->contradictions, 'legacy coherence positional signature');

echo "stats contract assertions passed\n";
