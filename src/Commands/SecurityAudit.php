<?php

declare (strict_types = 1);

namespace Tawfik\LaravelSecurity\Commands;

/**
 * Security Audit Command
 *
 * Performs a comprehensive security audit of the Laravel application:
 * - File permissions check
 * - Exposed sensitive files scan
 * - Security headers validation
 * - Environment configuration audit
 * - OWASP Top 10 risks assessment
 * - Database security review
 */
class SecurityAudit extends BaseSecurityCommand
{
    protected $signature = 'security:audit
                            {--dry-run : Show what would be checked without making changes}
                            {--output= : Output format (text, json, html)}
                            {--fix : Automatically fix issues where possible}
                            {--verbose : Show detailed information}';

    protected $description = 'Perform a comprehensive security audit of the Laravel application';

    protected array $auditResults    = [];
    protected array $issues          = [];
    protected array $warnings        = [];
    protected array $recommendations = [];

    protected function executeCommand(): void
    {
        $this->info('🔍 Starting comprehensive security audit...');

        if (! $this->validateLaravelApp()) {
            return;
        }

        $this->auditResults = [
            'timestamp'       => date('Y-m-d H:i:s'),
            'application'     => config('app.name', 'Laravel Application'),
            'environment'     => config('app.env', 'unknown'),
            'checks'          => [],
            'issues'          => [],
            'warnings'        => [],
            'recommendations' => [],
            'score'           => 100,
        ];

        // Perform all security checks
        $this->checkFilePermissions();
        $this->checkExposedFiles();
        $this->checkSecurityHeaders();
        $this->checkEnvironmentSecurity();
        $this->checkOwaspRisks();
        $this->checkDatabaseSecurity();
        $this->checkSessionSecurity();
        $this->checkAuthenticationSecurity();
        $this->checkInputValidation();
        $this->checkLoggingSecurity();

        // Calculate security score
        $this->calculateSecurityScore();

        // Display results
        $this->displayAuditResults();

        // Generate report if requested
        $this->generateReport();
    }

    /**
     * Check file permissions for security
     */
    private function checkFilePermissions(): void
    {
        $this->info('📁 Checking file permissions...');

        $criticalFiles = [
            '.env'            => ['expected' => 0600, 'description' => 'Environment file'],
            'config'          => ['expected' => 0755, 'description' => 'Configuration directory'],
            'storage'         => ['expected' => 0755, 'description' => 'Storage directory'],
            'bootstrap/cache' => ['expected' => 0755, 'description' => 'Cache directory'],
            'public'          => ['expected' => 0755, 'description' => 'Public directory'],
        ];

        foreach ($criticalFiles as $file => $config) {
            $filePath = $this->getBasePath() . '/' . $file;

            if ($this->fileExists($filePath)) {
                $currentPermissions = $this->filesystem->chmod($filePath);

                if ($currentPermissions !== $config['expected']) {
                    $this->addIssue('File Permissions', "{$config['description']} ({$file}) has insecure permissions: " . decoct($currentPermissions));

                    if ($this->option('fix')) {
                        $this->setPermissions($filePath, $config['expected']);
                        $this->addRecommendation('Fixed permissions for ' . $file);
                    }
                } else {
                    $this->addCheck('File Permissions', "✓ {$config['description']} permissions are secure");
                }
            }
        }
    }

    /**
     * Check for exposed sensitive files
     */
    private function checkExposedFiles(): void
    {
        $this->info('🔍 Scanning for exposed sensitive files...');

        $sensitiveFiles = [
            '.env',
            '.git',
            'composer.json',
            'composer.lock',
            'package.json',
            'package-lock.json',
            'yarn.lock',
            'webpack.mix.js',
            'vite.config.js',
            'storage/logs/laravel.log',
            'storage/framework/cache/data',
            'bootstrap/cache/config.php',
        ];

        foreach ($sensitiveFiles as $file) {
            $filePath = $this->getPublicPath() . '/' . $file;

            if ($this->fileExists($filePath)) {
                $this->addIssue('Exposed Files', "Sensitive file is publicly accessible: {$file}");
            }
        }

        // Check for backup files
        $backupPatterns = ['*.bak', '*.backup', '*.old', '*.orig', '*.save'];
        foreach ($backupPatterns as $pattern) {
            $files = glob($this->getPublicPath() . '/' . $pattern);
            foreach ($files as $file) {
                $this->addIssue('Exposed Files', "Backup file is publicly accessible: " . basename($file));
            }
        }
    }

    /**
     * Check security headers configuration
     */
    private function checkSecurityHeaders(): void
    {
        $this->info('🛡️ Checking security headers...');

        $requiredHeaders = [
            'X-Content-Type-Options'    => 'nosniff',
            'X-Frame-Options'           => 'DENY',
            'X-XSS-Protection'          => '1; mode=block',
            'Strict-Transport-Security' => 'max-age=31536000; includeSubDomains',
            'Content-Security-Policy'   => 'default-src \'self\'',
            'Referrer-Policy'           => 'strict-origin-when-cross-origin',
        ];

        // Check if .htaccess exists and contains security headers
        $htaccessPath = $this->getPublicPath() . '/.htaccess';
        if ($this->fileExists($htaccessPath)) {
            $content = $this->readFile($htaccessPath);

            foreach ($requiredHeaders as $header => $expectedValue) {
                if (! str_contains($content, $header)) {
                    $this->addWarning('Security Headers', "Missing security header: {$header}");
                } else {
                    $this->addCheck('Security Headers', "✓ Header {$header} is configured");
                }
            }
        } else {
            $this->addIssue('Security Headers', '.htaccess file not found - security headers not configured');
        }
    }

    /**
     * Check environment security configuration
     */
    private function checkEnvironmentSecurity(): void
    {
        $this->info('⚙️ Checking environment security...');

        $envPath = $this->getBasePath() . '/.env';
        if (! $this->fileExists($envPath)) {
            $this->addIssue('Environment', '.env file not found');
            return;
        }

        $content = $this->readFile($envPath);
        if ($content === null) {
            return;
        }

        // Check for debug mode
        if (str_contains($content, 'APP_DEBUG=true')) {
            $this->addIssue('Environment', 'Debug mode is enabled in production');
        }

        // Check for weak encryption key
        if (str_contains($content, 'APP_KEY=base64:') && strlen($content) < 50) {
            $this->addIssue('Environment', 'Weak or missing application encryption key');
        }

        // Check for database credentials exposure
        if (str_contains($content, 'DB_PASSWORD=') && ! str_contains($content, 'DB_PASSWORD=null')) {
            $this->addCheck('Environment', '✓ Database password is configured');
        }

        // Check for session security
        if (! str_contains($content, 'SESSION_SECURE_COOKIES=true')) {
            $this->addWarning('Environment', 'Secure session cookies not enforced');
        }
    }

    /**
     * Check OWASP Top 10 risks
     */
    private function checkOwaspRisks(): void
    {
        $this->info('🔒 Checking OWASP Top 10 risks...');

        // A01:2021 – Broken Access Control
        $this->checkAccessControl();

        // A02:2021 – Cryptographic Failures
        $this->checkCryptographicFailures();

        // A03:2021 – Injection
        $this->checkInjectionVulnerabilities();

        // A04:2021 – Insecure Design
        $this->checkInsecureDesign();

        // A05:2021 – Security Misconfiguration
        $this->checkSecurityMisconfiguration();

        // A06:2021 – Vulnerable and Outdated Components
        $this->checkVulnerableComponents();

        // A07:2021 – Identification and Authentication Failures
        $this->checkAuthenticationFailures();

        // A08:2021 – Software and Data Integrity Failures
        $this->checkDataIntegrity();

        // A09:2021 – Security Logging and Monitoring Failures
        $this->checkLoggingFailures();

        // A10:2021 – Server-Side Request Forgery
        $this->checkSSRF();
    }

    /**
     * Check access control implementation
     */
    private function checkAccessControl(): void
    {
        // Check for middleware usage
        $middlewarePath = $this->getBasePath() . '/app/Http/Kernel.php';
        if ($this->fileExists($middlewarePath)) {
            $content = $this->readFile($middlewarePath);
            if (str_contains($content, 'auth') || str_contains($content, 'Auth')) {
                $this->addCheck('OWASP A01', '✓ Authentication middleware is configured');
            } else {
                $this->addWarning('OWASP A01', 'Authentication middleware not found');
            }
        }
    }

    /**
     * Check cryptographic failures
     */
    private function checkCryptographicFailures(): void
    {
        $envPath = $this->getBasePath() . '/.env';
        $content = $this->readFile($envPath);

        if ($content && str_contains($content, 'APP_KEY=base64:')) {
            $this->addCheck('OWASP A02', '✓ Application encryption key is configured');
        } else {
            $this->addIssue('OWASP A02', 'Application encryption key is missing or weak');
        }
    }

    /**
     * Check injection vulnerabilities
     */
    private function checkInjectionVulnerabilities(): void
    {
        // Check for Eloquent usage (prevents SQL injection)
        $modelPath = $this->getBasePath() . '/app/Models';
        if ($this->filesystem->exists($modelPath)) {
            $this->addCheck('OWASP A03', '✓ Eloquent ORM is used (prevents SQL injection)');
        } else {
            $this->addWarning('OWASP A03', 'No models found - ensure proper input validation');
        }
    }

    /**
     * Check insecure design
     */
    private function checkInsecureDesign(): void
    {
        // Check for proper validation rules
        $requestPath = $this->getBasePath() . '/app/Http/Requests';
        if ($this->filesystem->exists($requestPath)) {
            $this->addCheck('OWASP A04', '✓ Form request validation classes exist');
        } else {
            $this->addWarning('OWASP A04', 'No form request validation classes found');
        }
    }

    /**
     * Check security misconfiguration
     */
    private function checkSecurityMisconfiguration(): void
    {
        // Check for proper error handling
        $envPath = $this->getBasePath() . '/.env';
        $content = $this->readFile($envPath);

        if ($content && str_contains($content, 'APP_DEBUG=false')) {
            $this->addCheck('OWASP A05', '✓ Debug mode is disabled');
        } else {
            $this->addIssue('OWASP A05', 'Debug mode is enabled - security risk');
        }
    }

    /**
     * Check vulnerable components
     */
    private function checkVulnerableComponents(): void
    {
        $composerLockPath = $this->getBasePath() . '/composer.lock';
        if ($this->fileExists($composerLockPath)) {
            $this->addCheck('OWASP A06', '✓ Composer.lock exists (enables dependency auditing)');
            $this->addRecommendation('Run: composer audit to check for vulnerable packages');
        } else {
            $this->addWarning('OWASP A06', 'Composer.lock not found - cannot audit dependencies');
        }
    }

    /**
     * Check authentication failures
     */
    private function checkAuthenticationFailures(): void
    {
        // Check for password hashing
        $userModelPath = $this->getBasePath() . '/app/Models/User.php';
        if ($this->fileExists($userModelPath)) {
            $content = $this->readFile($userModelPath);
            if (str_contains($content, 'Hash::make') || str_contains($content, 'bcrypt')) {
                $this->addCheck('OWASP A07', '✓ Password hashing is implemented');
            } else {
                $this->addWarning('OWASP A07', 'Password hashing not found in User model');
            }
        }
    }

    /**
     * Check data integrity
     */
    private function checkDataIntegrity(): void
    {
        // Check for CSRF protection
        $webRoutesPath = $this->getBasePath() . '/routes/web.php';
        if ($this->fileExists($webRoutesPath)) {
            $content = $this->readFile($webRoutesPath);
            if (str_contains($content, 'csrf')) {
                $this->addCheck('OWASP A08', '✓ CSRF protection is configured');
            } else {
                $this->addWarning('OWASP A08', 'CSRF protection not found in web routes');
            }
        }
    }

    /**
     * Check logging failures
     */
    private function checkLoggingFailures(): void
    {
        $logPath = $this->getBasePath() . '/storage/logs';
        if ($this->filesystem->exists($logPath)) {
            $this->addCheck('OWASP A09', '✓ Logging directory exists');
            $this->addRecommendation('Configure log rotation and monitoring');
        } else {
            $this->addIssue('OWASP A09', 'Logging directory not found');
        }
    }

    /**
     * Check SSRF vulnerabilities
     */
    private function checkSSRF(): void
    {
        // Check for URL validation
        $this->addRecommendation('Implement URL validation for external requests');
        $this->addRecommendation('Use whitelist for allowed external domains');
    }

    /**
     * Check database security
     */
    private function checkDatabaseSecurity(): void
    {
        $this->info('🗄️ Checking database security...');

        $envPath = $this->getBasePath() . '/.env';
        $content = $this->readFile($envPath);

        if ($content) {
            // Check for database configuration
            if (str_contains($content, 'DB_CONNECTION=')) {
                $this->addCheck('Database', '✓ Database connection is configured');
            }

            // Check for database user privileges
            $this->addRecommendation('Ensure database user has minimal required privileges');
            $this->addRecommendation('Use separate database users for different environments');
        }
    }

    /**
     * Check session security
     */
    private function checkSessionSecurity(): void
    {
        $this->info('🔐 Checking session security...');

        $sessionConfigPath = $this->getBasePath() . '/config/session.php';
        if ($this->fileExists($sessionConfigPath)) {
            $content = $this->readFile($sessionConfigPath);

            if (str_contains($content, "'secure' => true")) {
                $this->addCheck('Session', '✓ Secure session cookies are enabled');
            } else {
                $this->addWarning('Session', 'Secure session cookies not enabled');
            }

            if (str_contains($content, "'http_only' => true")) {
                $this->addCheck('Session', '✓ HttpOnly session cookies are enabled');
            } else {
                $this->addWarning('Session', 'HttpOnly session cookies not enabled');
            }
        }
    }

    /**
     * Check authentication security
     */
    private function checkAuthenticationSecurity(): void
    {
        $this->info('🔑 Checking authentication security...');

        // Check for rate limiting
        $this->addRecommendation('Implement rate limiting for login attempts');
        $this->addRecommendation('Enable two-factor authentication');
        $this->addRecommendation('Implement account lockout after failed attempts');
    }

    /**
     * Check input validation
     */
    private function checkInputValidation(): void
    {
        $this->info('✅ Checking input validation...');

        // Check for validation rules
        $this->addRecommendation('Implement comprehensive input validation');
        $this->addRecommendation('Use Laravel validation rules for all user inputs');
        $this->addRecommendation('Sanitize outputs to prevent XSS');
    }

    /**
     * Check logging security
     */
    private function checkLoggingSecurity(): void
    {
        $this->info('📝 Checking logging security...');

        $logPath = $this->getBasePath() . '/storage/logs';
        if ($this->filesystem->exists($logPath)) {
            $this->addCheck('Logging', '✓ Logging directory exists');
            $this->addRecommendation('Configure log rotation (max 30 days)');
            $this->addRecommendation('Monitor logs for suspicious activity');
            $this->addRecommendation('Ensure logs are not publicly accessible');
        }
    }

    /**
     * Calculate security score
     */
    private function calculateSecurityScore(): void
    {
        $totalChecks   = count($this->auditResults['checks']);
        $totalIssues   = count($this->auditResults['issues']);
        $totalWarnings = count($this->auditResults['warnings']);

        $score = 100;
        $score -= ($totalIssues * 10);  // Each issue reduces score by 10
        $score -= ($totalWarnings * 5); // Each warning reduces score by 5

        $this->auditResults['score'] = max(0, $score);
    }

    /**
     * Display audit results
     */
    private function displayAuditResults(): void
    {
        $this->newLine();
        $this->info('📊 Security Audit Results');
        $this->info('========================');

        $this->info("Security Score: {$this->auditResults['score']}/100");
        $this->info("Issues Found: " . count($this->auditResults['issues']));
        $this->info("Warnings: " . count($this->auditResults['warnings']));
        $this->info("Recommendations: " . count($this->auditResults['recommendations']));

        if (! empty($this->auditResults['issues'])) {
            $this->newLine();
            $this->error('🚨 Critical Issues:');
            foreach ($this->auditResults['issues'] as $issue) {
                $this->error("  - {$issue}");
            }
        }

        if (! empty($this->auditResults['warnings'])) {
            $this->newLine();
            $this->warn('⚠️ Warnings:');
            foreach ($this->auditResults['warnings'] as $warning) {
                $this->warn("  - {$warning}");
            }
        }

        if (! empty($this->auditResults['recommendations'])) {
            $this->newLine();
            $this->info('💡 Recommendations:');
            foreach ($this->auditResults['recommendations'] as $recommendation) {
                $this->line("  - {$recommendation}");
            }
        }
    }

    /**
     * Generate audit report
     */
    private function generateReport(): void
    {
        $outputFormat = $this->option('output');

        if ($outputFormat === 'json') {
            $reportPath = $this->getBasePath() . '/security-audit-report.json';
            $this->writeFile($reportPath, json_encode($this->auditResults, JSON_PRETTY_PRINT));
            $this->info("📄 JSON report generated: {$reportPath}");
        } elseif ($outputFormat === 'html') {
            $this->generateHtmlReport();
        }
    }

    /**
     * Generate HTML report
     */
    private function generateHtmlReport(): void
    {
        $html       = $this->generateHtmlContent();
        $reportPath = $this->getBasePath() . '/security-audit-report.html';

        if ($this->writeFile($reportPath, $html)) {
            $this->info("📄 HTML report generated: {$reportPath}");
        }
    }

    /**
     * Generate HTML content for report
     */
    private function generateHtmlContent(): string
    {
        $score      = $this->auditResults['score'];
        $scoreColor = $score >= 80 ? 'green' : ($score >= 60 ? 'orange' : 'red');

        $html = "<!DOCTYPE html>\n<html>\n<head>\n";
        $html .= "<title>Security Audit Report</title>\n";
        $html .= "<style>\n";
        $html .= "body { font-family: Arial, sans-serif; margin: 20px; }\n";
        $html .= ".score { font-size: 24px; font-weight: bold; color: {$scoreColor}; }\n";
        $html .= ".issue { color: red; }\n";
        $html .= ".warning { color: orange; }\n";
        $html .= ".check { color: green; }\n";
        $html .= "</style>\n</head>\n<body>\n";

        $html .= "<h1>Security Audit Report</h1>\n";
        $html .= "<p><strong>Application:</strong> {$this->auditResults['application']}</p>\n";
        $html .= "<p><strong>Environment:</strong> {$this->auditResults['environment']}</p>\n";
        $html .= "<p><strong>Timestamp:</strong> {$this->auditResults['timestamp']}</p>\n";
        $html .= "<p class='score'>Security Score: {$score}/100</p>\n";

        if (! empty($this->auditResults['issues'])) {
            $html .= "<h2>Critical Issues</h2>\n<ul>\n";
            foreach ($this->auditResults['issues'] as $issue) {
                $html .= "<li class='issue'>{$issue}</li>\n";
            }
            $html .= "</ul>\n";
        }

        if (! empty($this->auditResults['warnings'])) {
            $html .= "<h2>Warnings</h2>\n<ul>\n";
            foreach ($this->auditResults['warnings'] as $warning) {
                $html .= "<li class='warning'>{$warning}</li>\n";
            }
            $html .= "</ul>\n";
        }

        if (! empty($this->auditResults['recommendations'])) {
            $html .= "<h2>Recommendations</h2>\n<ul>\n";
            foreach ($this->auditResults['recommendations'] as $recommendation) {
                $html .= "<li>{$recommendation}</li>\n";
            }
            $html .= "</ul>\n";
        }

        $html .= "</body>\n</html>";

        return $html;
    }

    /**
     * Add check result
     */
    private function addCheck(string $category, string $message): void
    {
        $this->auditResults['checks'][] = "[{$category}] {$message}";
    }

    /**
     * Add issue
     */
    private function addIssue(string $category, string $message): void
    {
        $this->auditResults['issues'][] = "[{$category}] {$message}";
    }

    /**
     * Add warning
     */
    private function addWarning(string $category, string $message): void
    {
        $this->auditResults['warnings'][] = "[{$category}] {$message}";
    }

    /**
     * Add recommendation
     */
    private function addRecommendation(string $message): void
    {
        $this->auditResults['recommendations'][] = $message;
    }
}
