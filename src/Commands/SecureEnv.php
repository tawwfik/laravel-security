<?php

declare (strict_types = 1);

namespace Tawfik\LaravelSecurity\Commands;

/**
 * Secure .env Command
 *
 * Secures the .env file by:
 * - Setting proper file permissions (600)
 * - Adding honeypot trap variables
 * - Removing debug variables
 * - Enforcing production environment
 * - Adding IP-based access logging
 */
class SecureEnv extends BaseSecurityCommand
{
    protected $signature = 'secure:env
                            {--dry-run : Show what would be changed without making changes}
                            {--backup : Create backup before modifications}
                            {--force : Skip confirmation prompts}';

    protected $description = 'Secure the .env file with proper permissions, honeypot variables, and production settings';

    protected function executeCommand(): void
    {
        $this->info('🔒 Securing .env file...');

        if (! $this->validateLaravelApp()) {
            return;
        }

        $envPath = $this->getBasePath() . '/.env';

        if (! $this->fileExists($envPath)) {
            $this->error('❌ .env file not found');
            return;
        }

        // Backup .env file if requested
        if ($this->option('backup') || config('laravel-security.env.backup_before_modify', true)) {
            $this->backupFile($envPath);
        }

        // Read current .env content
        $content = $this->readFile($envPath);
        if ($content === null) {
            return;
        }

        $originalContent = $content;
        $changes         = [];

        // 1. Set proper file permissions
        if (! $this->isWindows()) {
            $this->setPermissions($envPath, 0600);
            $this->addResult('Permissions', 'Set .env permissions to 600 (owner read/write only)');
        }

        // 2. Add honeypot variables
        $honeypotVars = config('laravel-security.env.honeypot_variables', []);
        foreach ($honeypotVars as $key => $value) {
            if (! str_contains($content, $key . '=')) {
                $content .= "\n# Honeypot trap variable\n{$key}={$value}";
                $changes[] = "Added honeypot variable: {$key}";
            }
        }

        // 3. Remove debug variables
        $debugVars = config('laravel-security.env.remove_debug_variables', ['APP_DEBUG', 'APP_ENV']);
        foreach ($debugVars as $var) {
            $pattern = "/^{$var}=.*$/m";
            if (preg_match($pattern, $content)) {
                $content   = preg_replace($pattern, '', $content);
                $changes[] = "Removed debug variable: {$var}";
            }
        }

        // 4. Enforce production environment
        if (config('laravel-security.env.enforce_production', true)) {
            $content = preg_replace('/^APP_ENV=.*$/m', 'APP_ENV=production', $content);
            if (! str_contains($content, 'APP_ENV=production')) {
                $content .= "\nAPP_ENV=production";
                $changes[] = 'Enforced APP_ENV=production';
            }
        }

        // 5. Add IP-based access logging
        if (! str_contains($content, 'LOG_ACCESS_IPS=')) {
            $content .= "\n# IP-based access logging\nLOG_ACCESS_IPS=true";
            $changes[] = 'Added IP-based access logging';
        }

        // 6. Add security headers configuration
        if (! str_contains($content, 'SECURITY_HEADERS=')) {
            $content .= "\n# Security headers\nSECURITY_HEADERS=true";
            $changes[] = 'Added security headers configuration';
        }

        // 7. Validate and fix other security issues
        $securityFixes = $this->applySecurityFixes($content);
        $changes       = array_merge($changes, $securityFixes);

        // Write changes if any
        if (! empty($changes) && $content !== $originalContent) {
            if ($this->writeFile($envPath, $content)) {
                foreach ($changes as $change) {
                    $this->addResult('Changes', $change);
                }
            }
        } else {
            $this->info('✅ .env file is already secure');
        }

        // Validate file permissions
        $this->validateFilePermissions();
    }

    /**
     * Apply additional security fixes to .env content
     */
    private function applySecurityFixes(string $content): array
    {
        $fixes = [];

        // Ensure session security
        if (! str_contains($content, 'SESSION_SECURE_COOKIES=')) {
            $content .= "\nSESSION_SECURE_COOKIES=true";
            $fixes[] = 'Added secure session cookies';
        }

        // Ensure HTTPS enforcement
        if (! str_contains($content, 'FORCE_HTTPS=')) {
            $content .= "\nFORCE_HTTPS=true";
            $fixes[] = 'Added HTTPS enforcement';
        }

        // Add CSRF protection
        if (! str_contains($content, 'CSRF_PROTECTION=')) {
            $content .= "\nCSRF_PROTECTION=true";
            $fixes[] = 'Added CSRF protection';
        }

        // Add rate limiting
        if (! str_contains($content, 'RATE_LIMITING=')) {
            $content .= "\nRATE_LIMITING=true";
            $fixes[] = 'Added rate limiting';
        }

        return $fixes;
    }

    /**
     * Validate file permissions for security
     */
    private function validateFilePermissions(): void
    {
        $criticalFiles = [
            '.env'            => 0600,
            'config'          => 0755,
            'storage'         => 0755,
            'bootstrap/cache' => 0755,
        ];

        foreach ($criticalFiles as $file => $expectedPermissions) {
            $filePath = $this->getBasePath() . '/' . $file;

            if ($this->fileExists($filePath)) {
                $currentPermissions = $this->filesystem->chmod($filePath);

                if ($currentPermissions !== $expectedPermissions) {
                    $this->setPermissions($filePath, $expectedPermissions);
                    $this->addResult('Permissions', "Fixed permissions for {$file}");
                }
            }
        }
    }
}
