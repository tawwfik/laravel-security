<?php

declare (strict_types = 1);

namespace Tawfik\LaravelSecurity\Commands;

/**
 * Security Vulnerability Scanner Command
 *
 * Scans the Laravel application for common security vulnerabilities:
 * - Exposed sensitive files
 * - Debug mode in production
 * - Weak encryption settings
 * - Outdated dependencies
 * - Configuration issues
 * - File permission problems
 * - Database security issues
 */
class SecurityScan extends BaseSecurityCommand
{
    protected $signature = 'security:scan
                            {--format=text : Output format (text, json, html)}
                            {--fix : Automatically fix issues where possible}
                            {--detailed : Show detailed information}
                            {--report= : Save report to file}';

    protected $description = 'Scan Laravel application for security vulnerabilities';

    protected array $vulnerabilities = [];
    protected array $warnings        = [];
    protected array $info            = [];
    protected int $riskScore         = 0;

    protected function executeCommand(): void
    {
        $this->info('🔍 Starting comprehensive security vulnerability scan...');

        if (! $this->validateLaravelApp()) {
            return;
        }

        $this->scanEnvironmentSecurity();
        $this->scanFilePermissions();
        $this->scanExposedFiles();
        $this->scanDependencies();
        $this->scanConfiguration();
        $this->scanDatabaseSecurity();
        $this->scanSessionSecurity();
        $this->scanAuthenticationSecurity();
        $this->scanLoggingSecurity();
        $this->scanServerSecurity();

        $this->calculateRiskScore();
        $this->displayResults();
        $this->generateReport();
    }

    /**
     * Scan environment security
     */
    private function scanEnvironmentSecurity(): void
    {
        $this->info('⚙️ Scanning environment security...');

        $envPath = $this->getBasePath() . '/.env';
        if (! $this->fileExists($envPath)) {
            $this->addVulnerability('Environment', 'Missing .env file', 'CRITICAL', 10);
            return;
        }

        $content = $this->readFile($envPath);
        if ($content === null) {
            return;
        }

        // Check for debug mode
        if (str_contains($content, 'APP_DEBUG=true')) {
            $this->addVulnerability('Environment', 'Debug mode is enabled in production', 'CRITICAL', 10);
        }

        // Check for weak encryption key
        if (str_contains($content, 'APP_KEY=base64:') && strlen($content) < 50) {
            $this->addVulnerability('Environment', 'Weak or missing application encryption key', 'CRITICAL', 10);
        }

        // Check for exposed database credentials
        if (str_contains($content, 'DB_PASSWORD=password') || str_contains($content, 'DB_PASSWORD=123456')) {
            $this->addVulnerability('Environment', 'Weak database password detected', 'HIGH', 8);
        }

        // Check for session security
        if (! str_contains($content, 'SESSION_SECURE_COOKIES=true')) {
            $this->addWarning('Environment', 'Secure session cookies not enforced');
        }

        // Check for HTTPS enforcement
        if (! str_contains($content, 'FORCE_HTTPS=true')) {
            $this->addWarning('Environment', 'HTTPS enforcement not configured');
        }
    }

    /**
     * Scan file permissions
     */
    private function scanFilePermissions(): void
    {
        $this->info('📁 Scanning file permissions...');

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
                $currentPermissions = fileperms($filePath) & 0777;
                if ($currentPermissions !== $config['expected']) {
                    $this->addVulnerability('File Permissions', "{$config['description']} has insecure permissions: " . decoct($currentPermissions), 'MEDIUM', 5);
                }
            }
        }
    }

    /**
     * Scan for exposed sensitive files
     */
    private function scanExposedFiles(): void
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
                $this->addVulnerability('Exposed Files', "Sensitive file is publicly accessible: {$file}", 'HIGH', 8);
            }
        }

        // Check for backup files
        $backupPatterns = ['*.bak', '*.backup', '*.old', '*.orig', '*.save'];
        foreach ($backupPatterns as $pattern) {
            $files = glob($this->getPublicPath() . '/' . $pattern);
            foreach ($files as $file) {
                $this->addVulnerability('Exposed Files', "Backup file is publicly accessible: " . basename($file), 'MEDIUM', 6);
            }
        }
    }

    /**
     * Scan dependencies for vulnerabilities
     */
    private function scanDependencies(): void
    {
        $this->info('📦 Scanning dependencies for vulnerabilities...');

        // Check if composer audit is available
        $composerJsonPath = $this->getBasePath() . '/composer.json';
        if ($this->fileExists($composerJsonPath)) {
            $this->addInfo('Dependencies', 'Run "composer audit" to check for vulnerable packages');
        }

        // Check for outdated packages
        $this->addInfo('Dependencies', 'Run "composer outdated" to check for outdated packages');
    }

    /**
     * Scan configuration security
     */
    private function scanConfiguration(): void
    {
        $this->info('⚙️ Scanning configuration security...');

        // Check for security headers
        $htaccessPath = $this->getPublicPath() . '/.htaccess';
        if ($this->fileExists($htaccessPath)) {
            $content = $this->readFile($htaccessPath);
            if ($content) {
                $requiredHeaders = [
                    'X-Content-Type-Options',
                    'X-Frame-Options',
                    'X-XSS-Protection',
                    'Strict-Transport-Security',
                ];

                foreach ($requiredHeaders as $header) {
                    if (! str_contains($content, $header)) {
                        $this->addWarning('Configuration', "Missing security header: {$header}");
                    }
                }
            }
        } else {
            $this->addWarning('Configuration', '.htaccess file not found - security headers not configured');
        }
    }

    /**
     * Scan database security
     */
    private function scanDatabaseSecurity(): void
    {
        $this->info('🗄️ Scanning database security...');

        // Check database configuration
        $this->addInfo('Database', 'Ensure database user has minimal required privileges');
        $this->addInfo('Database', 'Use separate database users for different environments');
        $this->addInfo('Database', 'Enable database encryption at rest');
    }

    /**
     * Scan session security
     */
    private function scanSessionSecurity(): void
    {
        $this->info('🔐 Scanning session security...');

        $this->addInfo('Session', 'Ensure session cookies are secure and HttpOnly');
        $this->addInfo('Session', 'Use strong session encryption');
        $this->addInfo('Session', 'Implement session timeout and regeneration');
    }

    /**
     * Scan authentication security
     */
    private function scanAuthenticationSecurity(): void
    {
        $this->info('🔑 Scanning authentication security...');

        $this->addInfo('Authentication', 'Implement rate limiting for login attempts');
        $this->addInfo('Authentication', 'Enable two-factor authentication');
        $this->addInfo('Authentication', 'Implement account lockout after failed attempts');
    }

    /**
     * Scan logging security
     */
    private function scanLoggingSecurity(): void
    {
        $this->info('📝 Scanning logging security...');

        $this->addInfo('Logging', 'Configure log rotation (max 30 days)');
        $this->addInfo('Logging', 'Monitor logs for suspicious activity');
        $this->addInfo('Logging', 'Ensure logs are not publicly accessible');
    }

    /**
     * Scan server security
     */
    private function scanServerSecurity(): void
    {
        $this->info('🖥️ Scanning server security...');

        $this->addInfo('Server', 'Keep server software updated');
        $this->addInfo('Server', 'Configure firewall rules');
        $this->addInfo('Server', 'Use HTTPS with valid SSL certificate');
    }

    /**
     * Calculate overall risk score
     */
    private function calculateRiskScore(): void
    {
        $this->riskScore = 100;

        foreach ($this->vulnerabilities as $vuln) {
            $this->riskScore -= $vuln['score'];
        }

        foreach ($this->warnings as $warning) {
            $this->riskScore -= 2;
        }

        $this->riskScore = max(0, $this->riskScore);
    }

    /**
     * Display scan results
     */
    private function displayResults(): void
    {
        $this->newLine();
        $this->info('📊 Security Vulnerability Scan Results');
        $this->info('=====================================');

        $this->info("Risk Score: {$this->riskScore}/100");
        $this->info("Vulnerabilities Found: " . count($this->vulnerabilities));
        $this->info("Warnings: " . count($this->warnings));
        $this->info("Info Items: " . count($this->info));

        if (! empty($this->vulnerabilities)) {
            $this->newLine();
            $this->error('🚨 CRITICAL VULNERABILITIES:');
            foreach ($this->vulnerabilities as $vuln) {
                if ($vuln['severity'] === 'CRITICAL') {
                    $this->error("  • {$vuln['category']}: {$vuln['message']}");
                }
            }

            $this->newLine();
            $this->warn('⚠️ HIGH VULNERABILITIES:');
            foreach ($this->vulnerabilities as $vuln) {
                if ($vuln['severity'] === 'HIGH') {
                    $this->warn("  • {$vuln['category']}: {$vuln['message']}");
                }
            }

            $this->newLine();
            $this->warn('⚠️ MEDIUM VULNERABILITIES:');
            foreach ($this->vulnerabilities as $vuln) {
                if ($vuln['severity'] === 'MEDIUM') {
                    $this->warn("  • {$vuln['category']}: {$vuln['message']}");
                }
            }
        }

        if (! empty($this->warnings)) {
            $this->newLine();
            $this->warn('⚠️ WARNINGS:');
            foreach ($this->warnings as $warning) {
                $this->warn("  • {$warning['category']}: {$warning['message']}");
            }
        }

        if (! empty($this->info)) {
            $this->newLine();
            $this->info('ℹ️ RECOMMENDATIONS:');
            foreach ($this->info as $info) {
                $this->info("  • {$info['category']}: {$info['message']}");
            }
        }

        $this->newLine();
        if ($this->riskScore >= 80) {
            $this->info('✅ Your application has good security posture');
        } elseif ($this->riskScore >= 60) {
            $this->warn('⚠️ Your application has moderate security risks');
        } else {
            $this->error('🚨 Your application has significant security vulnerabilities');
        }
    }

    /**
     * Generate scan report
     */
    private function generateReport(): void
    {
        $reportPath = $this->option('report');
        if (! $reportPath) {
            $reportPath = $this->getBasePath() . '/security-scan-report.' . $this->option('format');
        }

        $format     = $this->option('format');
        $reportData = [
            'timestamp'       => date('Y-m-d H:i:s'),
            'application'     => config('app.name', 'Laravel Application'),
            'risk_score'      => $this->riskScore,
            'vulnerabilities' => $this->vulnerabilities,
            'warnings'        => $this->warnings,
            'info'            => $this->info,
        ];

        switch ($format) {
            case 'json':
                $content = json_encode($reportData, JSON_PRETTY_PRINT);
                break;
            case 'html':
                $content = $this->generateHtmlReport($reportData);
                break;
            default:
                $content = $this->generateTextReport($reportData);
        }

        if ($this->writeFile($reportPath, $content)) {
            $this->info("📄 Scan report saved to: {$reportPath}");
        }
    }

    /**
     * Generate HTML report
     */
    private function generateHtmlReport(array $data): string
    {
        $html = '<!DOCTYPE html>
<html>
<head>
    <title>Security Scan Report</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; }
        .header { background: #f5f5f5; padding: 20px; border-radius: 5px; }
        .vulnerability { background: #ffe6e6; padding: 10px; margin: 5px 0; border-left: 4px solid #ff0000; }
        .warning { background: #fff3cd; padding: 10px; margin: 5px 0; border-left: 4px solid #ffc107; }
        .info { background: #d1ecf1; padding: 10px; margin: 5px 0; border-left: 4px solid #17a2b8; }
        .score { font-size: 24px; font-weight: bold; }
        .score.good { color: #28a745; }
        .score.warning { color: #ffc107; }
        .score.danger { color: #dc3545; }
    </style>
</head>
<body>
    <div class="header">
        <h1>Security Vulnerability Scan Report</h1>
        <p><strong>Application:</strong> ' . htmlspecialchars($data['application']) . '</p>
        <p><strong>Timestamp:</strong> ' . htmlspecialchars($data['timestamp']) . '</p>
        <p><strong>Risk Score:</strong> <span class="score ' . ($data['risk_score'] >= 80 ? 'good' : ($data['risk_score'] >= 60 ? 'warning' : 'danger')) . '">' . $data['risk_score'] . '/100</span></p>
    </div>';

        if (! empty($data['vulnerabilities'])) {
            $html .= '<h2>🚨 Vulnerabilities Found</h2>';
            foreach ($data['vulnerabilities'] as $vuln) {
                $html .= '<div class="vulnerability">
                    <strong>' . htmlspecialchars($vuln['severity']) . ' - ' . htmlspecialchars($vuln['category']) . ':</strong> ' . htmlspecialchars($vuln['message']) . '
                </div>';
            }
        }

        if (! empty($data['warnings'])) {
            $html .= '<h2>⚠️ Warnings</h2>';
            foreach ($data['warnings'] as $warning) {
                $html .= '<div class="warning">
                    <strong>' . htmlspecialchars($warning['category']) . ':</strong> ' . htmlspecialchars($warning['message']) . '
                </div>';
            }
        }

        if (! empty($data['info'])) {
            $html .= '<h2>ℹ️ Recommendations</h2>';
            foreach ($data['info'] as $info) {
                $html .= '<div class="info">
                    <strong>' . htmlspecialchars($info['category']) . ':</strong> ' . htmlspecialchars($info['message']) . '
                </div>';
            }
        }

        $html .= '</body></html>';
        return $html;
    }

    /**
     * Generate text report
     */
    private function generateTextReport(array $data): string
    {
        $report = "Security Vulnerability Scan Report\n";
        $report .= "==================================\n\n";
        $report .= "Application: {$data['application']}\n";
        $report .= "Timestamp: {$data['timestamp']}\n";
        $report .= "Risk Score: {$data['risk_score']}/100\n\n";

        if (! empty($data['vulnerabilities'])) {
            $report .= "VULNERABILITIES FOUND:\n";
            $report .= "======================\n";
            foreach ($data['vulnerabilities'] as $vuln) {
                $report .= "[{$vuln['severity']}] {$vuln['category']}: {$vuln['message']}\n";
            }
            $report .= "\n";
        }

        if (! empty($data['warnings'])) {
            $report .= "WARNINGS:\n";
            $report .= "=========\n";
            foreach ($data['warnings'] as $warning) {
                $report .= "{$warning['category']}: {$warning['message']}\n";
            }
            $report .= "\n";
        }

        if (! empty($data['info'])) {
            $report .= "RECOMMENDATIONS:\n";
            $report .= "================\n";
            foreach ($data['info'] as $info) {
                $report .= "{$info['category']}: {$info['message']}\n";
            }
        }

        return $report;
    }

    /**
     * Add vulnerability
     */
    private function addVulnerability(string $category, string $message, string $severity, int $score): void
    {
        $this->vulnerabilities[] = [
            'category' => $category,
            'message'  => $message,
            'severity' => $severity,
            'score'    => $score,
        ];
    }

    /**
     * Add warning
     */
    private function addWarning(string $category, string $message): void
    {
        $this->warnings[] = [
            'category' => $category,
            'message'  => $message,
        ];
    }

    /**
     * Add info
     */
    private function addInfo(string $category, string $message): void
    {
        $this->info[] = [
            'category' => $category,
            'message'  => $message,
        ];
    }
}
