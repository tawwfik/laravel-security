<?php

declare (strict_types = 1);

namespace Tawfik\LaravelSecurity\Commands;

use Illuminate\Console\Command;
use Illuminate\Filesystem\Filesystem;
use Illuminate\Support\Facades\File;

/**
 * Base Security Command
 *
 * Provides common functionality for all security commands including
 * dry-run mode, colored output, and file system operations.
 */
abstract class BaseSecurityCommand extends Command
{
    protected Filesystem $filesystem;
    protected bool $dryRun   = false;
    protected array $results = [];

    public function __construct(Filesystem $filesystem)
    {
        parent::__construct();
        $this->filesystem = $filesystem;
    }

    /**
     * Execute the command
     */
    public function handle(): int
    {
        $this->dryRun = $this->option('dry-run');

        if ($this->dryRun) {
            $this->info('🔍 Running in DRY-RUN mode - no changes will be made');
        }

        $this->results = [];

        try {
            $this->executeCommand();
            $this->displayResults();
            return self::SUCCESS;
        } catch (\Exception $e) {
            $this->error('❌ Error: ' . $e->getMessage());
            return self::FAILURE;
        }
    }

    /**
     * Execute the specific command logic
     */
    abstract protected function executeCommand(): void;

    /**
     * Display command results
     */
    protected function displayResults(): void
    {
        if (empty($this->results)) {
            $this->info('✅ No changes required');
            return;
        }

        $this->newLine();
        $this->info('📊 Results Summary:');

        foreach ($this->results as $type => $items) {
            if (! empty($items)) {
                $this->line("  {$type}: " . count($items) . ' items');
                foreach ($items as $item) {
                    $this->line("    - {$item}");
                }
            }
        }
    }

    /**
     * Add result item
     */
    protected function addResult(string $type, string $message): void
    {
        if (! isset($this->results[$type])) {
            $this->results[$type] = [];
        }
        $this->results[$type][] = $message;
    }

    /**
     * Check if file exists and is readable
     */
    protected function fileExists(string $path): bool
    {
        return $this->filesystem->exists($path) && $this->filesystem->isReadable($path);
    }

    /**
     * Safely read file contents
     */
    protected function readFile(string $path): ?string
    {
        if (! $this->fileExists($path)) {
            return null;
        }

        try {
            return $this->filesystem->get($path);
        } catch (\Exception $e) {
            $this->warn("⚠️  Could not read file: {$path}");
            return null;
        }
    }

    /**
     * Safely write file contents
     */
    protected function writeFile(string $path, string $content): bool
    {
        if ($this->dryRun) {
            $this->line("📝 [DRY-RUN] Would write to: {$path}");
            return true;
        }

        try {
            $this->filesystem->put($path, $content);
            $this->info("✅ Written: {$path}");
            return true;
        } catch (\Exception $e) {
            $this->error("❌ Failed to write: {$path} - {$e->getMessage()}");
            return false;
        }
    }

    /**
     * Safely backup file
     */
    protected function backupFile(string $path): bool
    {
        if (! $this->fileExists($path)) {
            return false;
        }

        $backupPath = $path . '.backup.' . date('Y-m-d-H-i-s');

        if ($this->dryRun) {
            $this->line("📋 [DRY-RUN] Would backup: {$path} -> {$backupPath}");
            return true;
        }

        try {
            $this->filesystem->copy($path, $backupPath);
            $this->info("💾 Backup created: {$backupPath}");
            return true;
        } catch (\Exception $e) {
            $this->error("❌ Backup failed: {$path} - {$e->getMessage()}");
            return false;
        }
    }

    /**
     * Set file permissions
     */
    protected function setPermissions(string $path, int $permissions): bool
    {
        if ($this->dryRun) {
            $this->line("🔐 [DRY-RUN] Would set permissions {$permissions} on: {$path}");
            return true;
        }

        try {
            $this->filesystem->chmod($path, $permissions);
            $this->info("🔐 Permissions set: {$path} -> " . decoct($permissions));
            return true;
        } catch (\Exception $e) {
            $this->error("❌ Failed to set permissions: {$path} - {$e->getMessage()}");
            return false;
        }
    }

    /**
     * Check if running on Windows
     */
    protected function isWindows(): bool
    {
        return strtoupper(substr(PHP_OS, 0, 3)) === 'WIN';
    }

    /**
     * Validate Laravel application structure
     */
    protected function validateLaravelApp(): bool
    {
        $requiredFiles = [
            'app',
            'config',
            'public',
            'storage',
            'bootstrap',
        ];

        foreach ($requiredFiles as $file) {
            if (! $this->filesystem->exists($file)) {
                $this->error("❌ Not a valid Laravel application. Missing: {$file}");
                return false;
            }
        }

        return true;
    }

    /**
     * Get Laravel base path
     */
    protected function getBasePath(): string
    {
        return base_path();
    }

    /**
     * Get public path
     */
    protected function getPublicPath(): string
    {
        return public_path();
    }
}
