<?php

declare (strict_types = 1);

namespace Tawfik\LaravelSecurity;

use Illuminate\Support\ServiceProvider;
use Tawfik\LaravelSecurity\Commands\SecureAll;
use Tawfik\LaravelSecurity\Commands\SecureEnv;
use Tawfik\LaravelSecurity\Commands\SecureHtaccess;
use Tawfik\LaravelSecurity\Commands\SecureRobots;
use Tawfik\LaravelSecurity\Commands\SecureSecurityFile;
use Tawfik\LaravelSecurity\Commands\SecurityAudit;

/**
 * Laravel Security Service Provider
 *
 * This service provider registers all security commands and provides
 * auto-discovery for Laravel applications. It ensures zero external
 * dependencies beyond Laravel core components.
 */
class LaravelSecurityServiceProvider extends ServiceProvider
{
    /**
     * Register any application services.
     */
    public function register(): void
    {
        // Register configuration
        $this->mergeConfigFrom(
            __DIR__ . '/../config/laravel-security.php', 'laravel-security'
        );
    }

    /**
     * Bootstrap any application services.
     */
    public function boot(): void
    {
        // Publish configuration if running in console
        if ($this->app->runningInConsole()) {
            $this->publishes([
                __DIR__ . '/../config/laravel-security.php' => config_path('laravel-security.php'),
            ], 'laravel-security-config');

            // Register all security commands
            $this->commands([
                SecureEnv::class,
                SecureHtaccess::class,
                SecureSecurityFile::class,
                SecureRobots::class,
                SecureAll::class,
                SecurityAudit::class,
            ]);
        }

        // Register middleware
        $this->registerMiddleware();
    }

    /**
     * Register security middleware
     */
    private function registerMiddleware(): void
    {
        // Register security headers middleware
        $this->app['router']->aliasMiddleware('security.headers', \Tawfik\LaravelSecurity\Middleware\SecurityHeaders::class);

        // Register rate limiting middleware
        $this->app['router']->aliasMiddleware('security.ratelimit', \Tawfik\LaravelSecurity\Middleware\RateLimit::class);

        // Register CSRF protection middleware
        $this->app['router']->aliasMiddleware('security.csrf', \Tawfik\LaravelSecurity\Middleware\CsrfProtection::class);
    }
}
