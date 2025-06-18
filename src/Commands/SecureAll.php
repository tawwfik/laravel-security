<?php

declare (strict_types = 1);

namespace Tawfik\LaravelSecurity\Commands;

/**
 * Secure All Command
 *
 * Runs all security commands sequentially:
 * - secure:env
 * - secure:htaccess
 * - secure:security-file
 * - secure:robots
 * - security:audit
 *
 * Provides comprehensive summary and reporting
 */
class SecureAll extends BaseSecurityCommand
{
    protected $signature = 'secure:all
                            {--dry-run : Show what would be changed without making changes}
                            {--backup : Create backups before modifications}
                            {--skip-audit : Skip the security audit}
                            {--force : Skip confirmation prompts}';

    protected $description = 'Run all security commands to comprehensively secure the Laravel application';

    protected array $commandResults     = [];
    protected array $successfulCommands = [];
    protected array $failedCommands     = [];

    protected function executeCommand(): void
    {
        $this->info('🛡️ Starting comprehensive Laravel security hardening...');
        $this->newLine();

        if (! $this->validateLaravelApp()) {
            return;
        }

        // Confirm before proceeding (unless --force is used)
        if (! $this->option('force') && ! $this->dryRun) {
            if (! $this->confirm('This will modify your application files. Do you want to continue?')) {
                $this->info('Security hardening cancelled.');
                return;
            }
        }

        $startTime = microtime(true);

        // Run all security commands
        $this->runSecureEnv();
        $this->runSecureHtaccess();
        $this->runSecureSecurityFile();
        $this->runSecureRobots();

        if (! $this->option('skip-audit')) {
            $this->runSecurityAudit();
        }

        $endTime       = microtime(true);
        $executionTime = round($endTime - $startTime, 2);

        // Display comprehensive summary
        $this->displayComprehensiveSummary($executionTime);

        // Generate final report
        $this->generateFinalReport();
    }

    /**
     * Run secure:env command
     */
    private function runSecureEnv(): void
    {
        $this->info('🔒 Step 1/5: Securing .env file...');

        try {
            $command = new SecureEnv($this->filesystem);
            $command->setLaravel($this->getLaravel());

            // Pass options
            if ($this->option('dry-run')) {
                $command->input->setOption('dry-run', true);
            }
            if ($this->option('backup')) {
                $command->input->setOption('backup', true);
            }

            $result = $command->handle();

            if ($result === 0) {
                $this->successfulCommands[] = 'secure:env';
                $this->addResult('Commands', '✓ .env file secured successfully');
            } else {
                $this->failedCommands[] = 'secure:env';
                $this->addResult('Errors', '✗ Failed to secure .env file');
            }
        } catch (\Exception $e) {
            $this->failedCommands[] = 'secure:env';
            $this->addResult('Errors', '✗ Error securing .env: ' . $e->getMessage());
        }

        $this->newLine();
    }

    /**
     * Run secure:htaccess command
     */
    private function runSecureHtaccess(): void
    {
        $this->info('🔒 Step 2/5: Generating hardened .htaccess...');

        try {
            $command = new SecureHtaccess($this->filesystem);
            $command->setLaravel($this->getLaravel());

            if ($this->option('dry-run')) {
                $command->input->setOption('dry-run', true);
            }
            if ($this->option('backup')) {
                $command->input->setOption('backup', true);
            }

            $result = $command->handle();

            if ($result === 0) {
                $this->successfulCommands[] = 'secure:htaccess';
                $this->addResult('Commands', '✓ .htaccess file hardened successfully');
            } else {
                $this->failedCommands[] = 'secure:htaccess';
                $this->addResult('Errors', '✗ Failed to harden .htaccess file');
            }
        } catch (\Exception $e) {
            $this->failedCommands[] = 'secure:htaccess';
            $this->addResult('Errors', '✗ Error hardening .htaccess: ' . $e->getMessage());
        }

        $this->newLine();
    }

    /**
     * Run secure:security-file command
     */
    private function runSecureSecurityFile(): void
    {
        $this->info('🔒 Step 3/5: Creating security.txt file...');

        try {
            $command = new SecureSecurityFile($this->filesystem);
            $command->setLaravel($this->getLaravel());

            if ($this->option('dry-run')) {
                $command->input->setOption('dry-run', true);
            }

            $result = $command->handle();

            if ($result === 0) {
                $this->successfulCommands[] = 'secure:security-file';
                $this->addResult('Commands', '✓ security.txt file created successfully');
            } else {
                $this->failedCommands[] = 'secure:security-file';
                $this->addResult('Errors', '✗ Failed to create security.txt file');
            }
        } catch (\Exception $e) {
            $this->failedCommands[] = 'secure:security-file';
            $this->addResult('Errors', '✗ Error creating security.txt: ' . $e->getMessage());
        }

        $this->newLine();
    }

    /**
     * Run secure:robots command
     */
    private function runSecureRobots(): void
    {
        $this->info('🔒 Step 4/5: Generating secure robots.txt...');

        try {
            $command = new SecureRobots($this->filesystem);
            $command->setLaravel($this->getLaravel());

            if ($this->option('dry-run')) {
                $command->input->setOption('dry-run', true);
            }
            if ($this->option('backup')) {
                $command->input->setOption('backup', true);
            }

            $result = $command->handle();

            if ($result === 0) {
                $this->successfulCommands[] = 'secure:robots';
                $this->addResult('Commands', '✓ robots.txt file secured successfully');
            } else {
                $this->failedCommands[] = 'secure:robots';
                $this->addResult('Errors', '✗ Failed to secure robots.txt file');
            }
        } catch (\Exception $e) {
            $this->failedCommands[] = 'secure:robots';
            $this->addResult('Errors', '✗ Error securing robots.txt: ' . $e->getMessage());
        }

        $this->newLine();
    }

    /**
     * Run security:audit command
     */
    private function runSecurityAudit(): void
    {
        $this->info('🔒 Step 5/5: Performing security audit...');

        try {
            $command = new SecurityAudit($this->filesystem);
            $command->setLaravel($this->getLaravel());

            if ($this->option('dry-run')) {
                $command->input->setOption('dry-run', true);
            }

            $result = $command->handle();

            if ($result === 0) {
                $this->successfulCommands[] = 'security:audit';
                $this->addResult('Commands', '✓ Security audit completed successfully');
            } else {
                $this->failedCommands[] = 'security:audit';
                $this->addResult('Errors', '✗ Security audit failed');
            }
        } catch (\Exception $e) {
            $this->failedCommands[] = 'security:audit';
            $this->addResult('Errors', '✗ Error during security audit: ' . $e->getMessage());
        }

        $this->newLine();
    }

    /**
     * Display comprehensive summary
     */
    private function displayComprehensiveSummary(float $executionTime): void
    {
        $this->info('📊 Comprehensive Security Hardening Summary');
        $this->info('==========================================');
        $this->newLine();

        // Execution statistics
        $this->info("⏱️  Execution Time: {$executionTime} seconds");
        $this->info("✅ Successful Commands: " . count($this->successfulCommands));
        $this->info("❌ Failed Commands: " . count($this->failedCommands));
        $this->newLine();

        // Command results
        if (! empty($this->successfulCommands)) {
            $this->info('✅ Successful Operations:');
            foreach ($this->successfulCommands as $command) {
                $this->line("  - {$command}");
            }
            $this->newLine();
        }

        if (! empty($this->failedCommands)) {
            $this->error('❌ Failed Operations:');
            foreach ($this->failedCommands as $command) {
                $this->error("  - {$command}");
            }
            $this->newLine();
        }

        // Security improvements summary
        $this->info('🛡️ Security Improvements Applied:');
        $this->line('  • Environment file secured with proper permissions');
        $this->line('  • Honeypot variables added to .env');
        $this->line('  • Debug mode disabled for production');
        $this->line('  • Hardened .htaccess with security headers');
        $this->line('  • HTTPS enforcement and HSTS configured');
        $this->line('  • Content Security Policy implemented');
        $this->line('  • Malicious user-agent blocking');
        $this->line('  • RFC 9116 compliant security.txt created');
        $this->line('  • RFC 8615 change-password file created');
        $this->line('  • Secure robots.txt with crawl protection');
        $this->line('  • Comprehensive security audit performed');
        $this->newLine();

        // Next steps recommendations
        $this->info('💡 Next Steps Recommendations:');
        $this->line('  • Review and customize security configurations');
        $this->line('  • Test your application thoroughly');
        $this->line('  • Set up monitoring and alerting');
        $this->line('  • Regularly run security:audit command');
        $this->line('  • Keep dependencies updated');
        $this->line('  • Monitor security logs');
        $this->newLine();

        // Success/failure message
        if (empty($this->failedCommands)) {
            $this->info('🎉 All security hardening operations completed successfully!');
            $this->info('Your Laravel application is now significantly more secure.');
        } else {
            $this->warn('⚠️  Some operations failed. Please review the errors above.');
            $this->info('Consider running individual commands to resolve issues.');
        }
    }

    /**
     * Generate final report
     */
    private function generateFinalReport(): void
    {
        $reportPath = $this->getBasePath() . '/security-hardening-report.txt';

        $report = "# Laravel Security Hardening Report\n";
        $report .= "# Generated: " . date('Y-m-d H:i:s') . "\n";
        $report .= "# Application: " . config('app.name', 'Laravel Application') . "\n\n";

        $report .= "## Execution Summary\n";
        $report .= "Successful Commands: " . count($this->successfulCommands) . "\n";
        $report .= "Failed Commands: " . count($this->failedCommands) . "\n\n";

        if (! empty($this->successfulCommands)) {
            $report .= "## Successful Operations\n";
            foreach ($this->successfulCommands as $command) {
                $report .= "- {$command}\n";
            }
            $report .= "\n";
        }

        if (! empty($this->failedCommands)) {
            $report .= "## Failed Operations\n";
            foreach ($this->failedCommands as $command) {
                $report .= "- {$command}\n";
            }
            $report .= "\n";
        }

        $report .= "## Security Improvements\n";
        $report .= "- Environment file secured\n";
        $report .= "- .htaccess hardened with security headers\n";
        $report .= "- security.txt created (RFC 9116)\n";
        $report .= "- robots.txt secured\n";
        $report .= "- Security audit performed\n\n";

        $report .= "## Recommendations\n";
        $report .= "- Review and customize configurations\n";
        $report .= "- Test application thoroughly\n";
        $report .= "- Set up monitoring and alerting\n";
        $report .= "- Run security:audit regularly\n";
        $report .= "- Keep dependencies updated\n";

        if ($this->writeFile($reportPath, $report)) {
            $this->info("📄 Final report generated: {$reportPath}");
        }
    }
}
