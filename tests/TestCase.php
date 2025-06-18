<?php

declare (strict_types = 1);

namespace Tawfik\LaravelSecurity\Tests;

use Orchestra\Testbench\TestCase as Orchestra;
use Tawfik\LaravelSecurity\LaravelSecurityServiceProvider;

/**
 * Base Test Case for Laravel Security Package
 */
abstract class TestCase extends Orchestra
{
    /**
     * Get package providers.
     */
    protected function getPackageProviders($app): array
    {
        return [
            LaravelSecurityServiceProvider::class,
        ];
    }

    /**
     * Define environment setup.
     */
    protected function defineEnvironment($app): void
    {
        // Set up test environment
        $app['config']->set('app.key', 'base64:test-key-for-testing-purposes-only');
        $app['config']->set('app.env', 'testing');
        $app['config']->set('app.debug', false);
    }

    /**
     * Get application timezone.
     */
    protected function getApplicationTimezone($app): string
    {
        return 'UTC';
    }
}
