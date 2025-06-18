<?php

declare (strict_types = 1);

namespace Tawfik\LaravelSecurity\Tests\Unit;

use Illuminate\Filesystem\Filesystem;
use Tawfik\LaravelSecurity\Commands\SecureEnv;
use Tawfik\LaravelSecurity\Tests\TestCase;

/**
 * SecureEnv Command Test
 */
class SecureEnvTest extends TestCase
{
    protected function setUp(): void
    {
        parent::setUp();

        // Create test environment
        $this->app['config']->set('laravel-security.env.backup_before_modify', false);
        $this->app['config']->set('laravel-security.env.honeypot_variables', [
            'FAKE_DB_PASSWORD' => 'honeypot_test',
        ]);
    }

    /** @test */
    public function it_can_secure_env_file()
    {
        // This is a basic test structure
        // In a real implementation, you would test the actual command functionality

        $filesystem = new Filesystem();
        $command    = new SecureEnv($filesystem);

        $this->assertInstanceOf(SecureEnv::class, $command);
        $this->assertEquals('secure:env', $command->getName());
    }

    /** @test */
    public function it_has_correct_signature()
    {
        $filesystem = new Filesystem();
        $command    = new SecureEnv($filesystem);

        $signature = $command->getSignature();

        $this->assertStringContainsString('secure:env', $signature);
        $this->assertStringContainsString('--dry-run', $signature);
        $this->assertStringContainsString('--backup', $signature);
    }

    /** @test */
    public function it_has_correct_description()
    {
        $filesystem = new Filesystem();
        $command    = new SecureEnv($filesystem);

        $description = $command->getDescription();

        $this->assertStringContainsString('Secure the .env file', $description);
    }
}
