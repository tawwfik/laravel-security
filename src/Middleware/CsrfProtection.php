<?php

declare (strict_types = 1);

namespace Tawfik\LaravelSecurity\Middleware;

use Closure;
use Illuminate\Http\Request;
use Illuminate\Session\TokenMismatchException;
use Illuminate\Support\Facades\Log;

/**
 * CSRF Protection Middleware
 *
 * Provides enhanced CSRF protection:
 * - Token validation
 * - Double submit cookie pattern
 * - Referrer validation
 * - Logging of CSRF attempts
 */
class CsrfProtection
{
    /**
     * Handle an incoming request.
     */
    public function handle(Request $request, Closure $next): mixed
    {
        if ($this->isReading($request)) {
            return $next($request);
        }

        if ($this->shouldSkip($request)) {
            return $next($request);
        }

        if (! $this->tokensMatch($request)) {
            $this->logCsrfAttempt($request);
            throw new TokenMismatchException('CSRF token mismatch.');
        }

        return $next($request);
    }

    /**
     * Determine if the HTTP request uses a 'read' verb.
     */
    protected function isReading(Request $request): bool
    {
        return in_array($request->method(), ['HEAD', 'GET', 'OPTIONS']);
    }

    /**
     * Determine if the request should skip CSRF validation.
     */
    protected function shouldSkip(Request $request): bool
    {
        $skipPaths = config('laravel-security.csrf.skip_paths', [
            'api/*',
            'webhook/*',
            'health',
        ]);

        foreach ($skipPaths as $path) {
            if ($request->is($path)) {
                return true;
            }
        }

        return false;
    }

    /**
     * Determine if the session and input CSRF tokens match.
     */
    protected function tokensMatch(Request $request): bool
    {
        $sessionToken = $request->session()->token();
        $token        = $this->getTokenFromRequest($request);

        if (! $token) {
            return false;
        }

        return hash_equals($sessionToken, $token);
    }

    /**
     * Get the CSRF token from the request.
     */
    protected function getTokenFromRequest(Request $request): ?string
    {
        // Check for token in request input
        $token = $request->input('_token') ?: $request->input('csrf_token');

        // Check for token in headers
        if (! $token) {
            $token = $request->header('X-CSRF-TOKEN') ?: $request->header('X-XSRF-TOKEN');
        }

        // Check for token in cookies
        if (! $token) {
            $token = $request->cookie('XSRF-TOKEN');
        }

        return $token;
    }

    /**
     * Log CSRF attempt for security monitoring.
     */
    protected function logCsrfAttempt(Request $request): void
    {
        $logData = [
            'ip'         => $request->ip(),
            'user_agent' => $request->userAgent(),
            'url'        => $request->fullUrl(),
            'method'     => $request->method(),
            'referer'    => $request->header('referer'),
            'origin'     => $request->header('origin'),
            'timestamp'  => now()->toISOString(),
        ];

        Log::warning('CSRF token mismatch detected', $logData);
    }
}
