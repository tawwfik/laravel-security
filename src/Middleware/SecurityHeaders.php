<?php

declare (strict_types = 1);

namespace Tawfik\LaravelSecurity\Middleware;

use Closure;
use Illuminate\Http\Request;
use Illuminate\Http\Response;
use Symfony\Component\HttpFoundation\Response as SymfonyResponse;

/**
 * Security Headers Middleware
 *
 * Adds comprehensive security headers to all HTTP responses:
 * - HSTS (HTTP Strict Transport Security)
 * - Content Security Policy
 * - X-Frame-Options
 * - X-Content-Type-Options
 * - X-XSS-Protection
 * - Referrer-Policy
 * - Permissions-Policy
 */
class SecurityHeaders
{
    /**
     * Handle an incoming request.
     */
    public function handle(Request $request, Closure $next): mixed
    {
        $response = $next($request);

        if ($response instanceof SymfonyResponse) {
            $this->addSecurityHeaders($response);
        }

        return $response;
    }

    /**
     * Add security headers to the response
     */
    private function addSecurityHeaders(SymfonyResponse $response): void
    {
        $headers = config('laravel-security.htaccess.security_headers', []);

        // Add default security headers if not configured
        if (empty($headers)) {
            $headers = [
                'X-Content-Type-Options' => 'nosniff',
                'X-Frame-Options'        => 'DENY',
                'X-XSS-Protection'       => '1; mode=block',
                'Referrer-Policy'        => 'strict-origin-when-cross-origin',
                'Permissions-Policy'     => 'camera=(), microphone=(), geolocation=(), payment=(), usb=()',
            ];
        }

        // Add HSTS header
        $hstsConfig = config('laravel-security.htaccess.hsts', []);
        if ($hstsConfig['enabled'] ?? true) {
            $hstsValue = 'max-age=' . ($hstsConfig['max_age'] ?? 31536000);
            if ($hstsConfig['include_subdomains'] ?? true) {
                $hstsValue .= '; includeSubDomains';
            }
            if ($hstsConfig['preload'] ?? true) {
                $hstsValue .= '; preload';
            }
            $response->headers->set('Strict-Transport-Security', $hstsValue);
        }

        // Add Content Security Policy
        $cspConfig = config('laravel-security.htaccess.csp', []);
        if ($cspConfig['enabled'] ?? true) {
            $cspDirectives = [];
            foreach ($cspConfig as $directive => $value) {
                if ($directive !== 'enabled') {
                    $cspDirectives[] = "{$directive} {$value}";
                }
            }
            $cspValue = implode('; ', $cspDirectives);
            $response->headers->set('Content-Security-Policy', $cspValue);
        }

        // Add configured security headers
        foreach ($headers as $header => $value) {
            $response->headers->set($header, $value);
        }

        // Add additional security headers
        $this->addAdditionalHeaders($response);
    }

    /**
     * Add additional security headers
     */
    private function addAdditionalHeaders(SymfonyResponse $response): void
    {
        // Remove server information
        $response->headers->remove('Server');
        $response->headers->remove('X-Powered-By');

        // Add cache control for sensitive pages
        if ($this->isSensitivePage()) {
            $response->headers->set('Cache-Control', 'no-store, no-cache, must-revalidate, max-age=0');
            $response->headers->set('Pragma', 'no-cache');
            $response->headers->set('Expires', '0');
        }

        // Add feature policy (legacy)
        if (! $response->headers->has('Permissions-Policy')) {
            $response->headers->set('Feature-Policy', "camera 'none'; microphone 'none'; geolocation 'none'");
        }
    }

    /**
     * Check if current page is sensitive
     */
    private function isSensitivePage(): bool
    {
        $sensitivePaths = [
            '/login',
            '/admin',
            '/dashboard',
            '/profile',
            '/settings',
            '/api/',
        ];

        $currentPath = request()->path();

        foreach ($sensitivePaths as $path) {
            if (str_starts_with($currentPath, trim($path, '/'))) {
                return true;
            }
        }

        return false;
    }
}
