<?php

declare (strict_types = 1);

namespace Tawfik\LaravelSecurity\Middleware;

use Closure;
use Illuminate\Cache\RateLimiter;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Log;
use Symfony\Component\HttpFoundation\Response;

/**
 * Rate Limit Middleware
 *
 * Provides rate limiting functionality for security:
 * - Login attempt rate limiting
 * - API request rate limiting
 * - IP-based blocking
 * - Brute force protection
 */
class RateLimit
{
    protected RateLimiter $limiter;

    public function __construct(RateLimiter $limiter)
    {
        $this->limiter = $limiter;
    }

    /**
     * Handle an incoming request.
     */
    public function handle(Request $request, Closure $next, string $type = 'default'): mixed
    {
        $key = $this->resolveRequestSignature($request, $type);

        if ($this->limiter->tooManyAttempts($key, $this->getMaxAttempts($type))) {
            $this->handleTooManyAttempts($request, $key, $type);
        }

        $this->limiter->hit($key, $this->getDecayMinutes($type) * 60);

        $response = $next($request);

        return $this->addHeaders(
            $response, $this->getMaxAttempts($type), $this->calculateRemainingAttempts($key, $type)
        );
    }

    /**
     * Resolve the request signature for rate limiting
     */
    protected function resolveRequestSignature(Request $request, string $type): string
    {
        $identifier = match ($type) {
            'login' => $request->input('email', $request->ip()),
            'api' => $request->bearerToken() ?: $request->ip(),
            'ip' => $request->ip(),
            default => $request->ip(),
        };

        return sha1($identifier . '|' . $type);
    }

    /**
     * Get maximum attempts for the given type
     */
    protected function getMaxAttempts(string $type): int
    {
        return match ($type) {
            'login' => config('laravel-security.rate_limiting.login_attempts.max_attempts', 5),
            'api' => config('laravel-security.rate_limiting.api_requests.max_attempts', 60),
            default => 60,
        };
    }

    /**
     * Get decay minutes for the given type
     */
    protected function getDecayMinutes(string $type): int
    {
        return match ($type) {
            'login' => config('laravel-security.rate_limiting.login_attempts.decay_minutes', 15),
            'api' => config('laravel-security.rate_limiting.api_requests.decay_minutes', 1),
            default => 1,
        };
    }

    /**
     * Handle too many attempts
     */
    protected function handleTooManyAttempts(Request $request, string $key, string $type): void
    {
        $retryAfter = $this->limiter->availableIn($key);

        // Log the rate limit violation
        $this->logRateLimitViolation($request, $type, $retryAfter);

        // Check if we should block the IP
        if ($this->shouldBlockIP($request, $type)) {
            $this->blockIP($request->ip());
        }

        abort(429, 'Too Many Attempts.', [
            'Retry-After'       => $retryAfter,
            'X-RateLimit-Reset' => $this->limiter->availableAt($key),
        ]);
    }

    /**
     * Calculate remaining attempts
     */
    protected function calculateRemainingAttempts(string $key, string $type): int
    {
        return $this->getMaxAttempts($type) - $this->limiter->attempts($key);
    }

    /**
     * Add rate limit headers to response
     */
    protected function addHeaders(Response $response, int $maxAttempts, int $remainingAttempts): Response
    {
        return $response->header('X-RateLimit-Limit', $maxAttempts)
            ->header('X-RateLimit-Remaining', $remainingAttempts);
    }

    /**
     * Log rate limit violation
     */
    protected function logRateLimitViolation(Request $request, string $type, int $retryAfter): void
    {
        $logData = [
            'ip'          => $request->ip(),
            'user_agent'  => $request->userAgent(),
            'type'        => $type,
            'retry_after' => $retryAfter,
            'url'         => $request->fullUrl(),
            'method'      => $request->method(),
        ];

        Log::warning('Rate limit violation detected', $logData);
    }

    /**
     * Check if IP should be blocked
     */
    protected function shouldBlockIP(Request $request, string $type): bool
    {
        if ($type !== 'login') {
            return false;
        }

        $key      = 'blocked_ips:' . $request->ip();
        $attempts = $this->limiter->attempts($key);

        return $attempts >= config('laravel-security.brute_force.max_attempts', 5);
    }

    /**
     * Block IP address
     */
    protected function blockIP(string $ip): void
    {
        $blockKey      = 'blocked_ips:' . $ip;
        $blockDuration = config('laravel-security.brute_force.lockout_duration', 900);

        $this->limiter->hit($blockKey, $blockDuration);

        Log::alert('IP address blocked due to brute force attempts', [
            'ip'       => $ip,
            'duration' => $blockDuration,
        ]);
    }
}
