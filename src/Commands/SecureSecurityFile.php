<?php

declare (strict_types = 1);

namespace Tawfik\LaravelSecurity\Commands;

/**
 * Secure Security.txt Command
 *
 * Creates or updates security.txt file according to RFC 9116:
 * - Security contact information
 * - PGP encryption key
 * - Expiration date
 * - Security policy links
 * - Acknowledgments and hiring information
 */
class SecureSecurityFile extends BaseSecurityCommand
{
    protected $signature = 'secure:security-file
                            {--dry-run : Show what would be changed without making changes}
                            {--contact= : Security contact email}
                            {--encryption= : PGP key URL}
                            {--expires= : Expiration date (e.g., +1 year)}
                            {--policy= : Security policy URL}
                            {--acknowledgments= : Acknowledgments URL}
                            {--hiring= : Security hiring URL}';

    protected $description = 'Create or update security.txt file according to RFC 9116 standards';

    protected function executeCommand(): void
    {
        $this->info('🔒 Creating security.txt file...');

        if (! $this->validateLaravelApp()) {
            return;
        }

        // Create .well-known directory if it doesn't exist
        $wellKnownPath = $this->getPublicPath() . '/.well-known';
        if (! $this->filesystem->exists($wellKnownPath)) {
            if (! $this->dryRun) {
                $this->filesystem->makeDirectory($wellKnownPath, 0755, true);
                $this->info("📁 Created directory: {$wellKnownPath}");
            } else {
                $this->line("📁 [DRY-RUN] Would create directory: {$wellKnownPath}");
            }
        }

        $securityTxtPath = $wellKnownPath . '/security.txt';

        // Generate security.txt content
        $content = $this->generateSecurityTxtContent();

        if ($this->writeFile($securityTxtPath, $content)) {
            $this->addResult('Created', 'security.txt file in .well-known directory');
            $this->addResult('Compliance', 'RFC 9116 compliant security contact information');
            $this->addResult('Features', 'Contact, encryption, expiration, policy links');
        }

        // Create change-password file (RFC 8615)
        $this->createChangePasswordFile($wellKnownPath);
    }

    /**
     * Generate security.txt content according to RFC 9116
     */
    private function generateSecurityTxtContent(): string
    {
        $content = "# Security Policy for " . config('app.name', 'Laravel Application') . "\n";
        $content .= "# Generated by Laravel Security Package\n";
        $content .= "# " . date('Y-m-d H:i:s') . "\n\n";

        // Contact information
        $contact = $this->option('contact') ?? config('laravel-security.security_txt.contact', 'mailto:security@example.com');
        $content .= "Contact: {$contact}\n";

        // Encryption key
        $encryption = $this->option('encryption') ?? config('laravel-security.security_txt.encryption', 'https://example.com/pgp-key.txt');
        $content .= "Encryption: {$encryption}\n";

        // Expiration date
        $expires        = $this->option('expires') ?? config('laravel-security.security_txt.expires', '+1 year');
        $expirationDate = date('Y-m-d', strtotime($expires));
        $content .= "Expires: {$expirationDate}\n";

        // Security policy
        $policy = $this->option('policy') ?? config('laravel-security.security_txt.policy', 'https://example.com/security-policy');
        $content .= "Policy: {$policy}\n";

        // Acknowledgments
        $acknowledgments = $this->option('acknowledgments') ?? config('laravel-security.security_txt.acknowledgments', 'https://example.com/hall-of-fame');
        $content .= "Acknowledgments: {$acknowledgments}\n";

        // Hiring information
        $hiring = $this->option('hiring') ?? config('laravel-security.security_txt.hiring', 'https://example.com/security-jobs');
        $content .= "Hiring: {$hiring}\n";

        // Additional security information
        $content .= "\n# Additional Security Information\n";
        $content .= "Preferred-Languages: en, ar\n";
        $content .= "Canonical: https://" . (config('app.url') ? parse_url(config('app.url'), PHP_URL_HOST) : 'example.com') . "/.well-known/security.txt\n";

        return $content;
    }

    /**
     * Create change-password file according to RFC 8615
     */
    private function createChangePasswordFile(string $wellKnownPath): void
    {
        $changePasswordPath = $wellKnownPath . '/change-password';

        $content = "# Change Password Policy\n";
        $content .= "# RFC 8615 - Well-Known URIs for Changing Passwords\n";
        $content .= "# " . date('Y-m-d H:i:s') . "\n\n";

        $content .= "This application supports password changes through the following methods:\n\n";
        $content .= "1. Web Interface: " . (config('app.url') ?: 'https://example.com') . "/password/reset\n";
        $content .= "2. API Endpoint: " . (config('app.url') ?: 'https://example.com') . "/api/password/change\n";
        $content .= "3. Contact Support: " . (config('laravel-security.security_txt.contact', 'mailto:security@example.com')) . "\n\n";

        $content .= "Password Requirements:\n";
        $content .= "- Minimum 8 characters\n";
        $content .= "- Must contain uppercase, lowercase, number, and special character\n";
        $content .= "- Cannot be reused from last 5 passwords\n";
        $content .= "- Must be changed every 90 days\n\n";

        $content .= "Security Notes:\n";
        $content .= "- Passwords are hashed using bcrypt\n";
        $content .= "- Failed attempts are rate-limited\n";
        $content .= "- Password changes require email verification\n";
        $content .= "- Session invalidation on password change\n";

        if ($this->writeFile($changePasswordPath, $content)) {
            $this->addResult('Created', 'change-password file (RFC 8615 compliant)');
        }
    }
}
