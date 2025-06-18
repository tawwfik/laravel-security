<?php

declare (strict_types = 1);

return [
    /*
    |--------------------------------------------------------------------------
    | Security Configuration
    |--------------------------------------------------------------------------
    |
    | This file contains all security-related configuration options for
    | the Laravel Security package. Modify these settings according to
    | your application's security requirements.
    |
    */

    /*
    |--------------------------------------------------------------------------
    | Environment Security Settings
    |--------------------------------------------------------------------------
    */
    'env'           => [
        'backup_before_modify'   => true,
        'honeypot_variables'     => [
            'FAKE_DB_PASSWORD' => 'honeypot_' . bin2hex(random_bytes(16)),
            'FAKE_API_KEY'     => 'honeypot_' . bin2hex(random_bytes(16)),
            'FAKE_SECRET_KEY'  => 'honeypot_' . bin2hex(random_bytes(16)),
        ],
        'remove_debug_variables' => [
            'APP_DEBUG',
            'APP_ENV',
        ],
        'enforce_production'     => true,
        'file_permissions'       => [
            '.env'            => 0600,
            'config'          => 0755,
            'storage'         => 0755,
            'bootstrap/cache' => 0755,
        ],
    ],

    /*
    |--------------------------------------------------------------------------
    | .htaccess Security Settings
    |--------------------------------------------------------------------------
    */
    'htaccess'      => [
        'blocked_files'       => [
            '.env',
            '.git',
            'storage/*',
            'vendor/*',
            'node_modules/*',
            '*.bak',
            '*.log',
            '*.sql',
            'composer.json',
            'composer.lock',
            'package.json',
            'package-lock.json',
            'yarn.lock',
            'webpack.mix.js',
            'vite.config.js',
        ],
        'blocked_user_agents' => [
            'bot',
            'crawler',
            'spider',
            'scanner',
            'nmap',
            'sqlmap',
            'nikto',
            'dirbuster',
            'gobuster',
        ],
        'security_headers'    => [
            'X-Content-Type-Options' => 'nosniff',
            'X-Frame-Options'        => 'DENY',
            'X-XSS-Protection'       => '1; mode=block',
            'Referrer-Policy'        => 'strict-origin-when-cross-origin',
            'Permissions-Policy'     => 'camera=(), microphone=(), geolocation=(), payment=(), usb=()',
        ],
        'hsts'                => [
            'enabled'            => true,
            'max_age'            => 31536000, // 1 year
            'include_subdomains' => true,
            'preload'            => true,
        ],
        'csp'                 => [
            'enabled'       => true,
            'policy'        => "default-src 'self'; script-src 'self' 'unsafe-inline' 'unsafe-eval'; style-src 'self' 'unsafe-inline'; img-src 'self' data: https:; font-src 'self' data:; connect-src 'self'; frame-ancestors 'none';",
            'nonce_enabled' => false,
            'report_only'   => false,
            'report_uri'    => null,
        ],
        'disable_for_routes'  => [
            // Routes where security headers should be disabled
            // 'api/*',
            // 'webhooks/*',
        ],
        'custom_headers'      => [
            // Add custom security headers
            // 'X-Custom-Security' => 'value',
        ],
    ],

    /*
    |--------------------------------------------------------------------------
    | Security.txt Configuration
    |--------------------------------------------------------------------------
    */
    'security_txt'  => [
        'contact'         => 'mailto:security@example.com',
        'encryption'      => 'https://example.com/pgp-key.txt',
        'expires'         => '+1 year',
        'acknowledgments' => 'https://example.com/hall-of-fame',
        'policy'          => 'https://example.com/security-policy',
        'hiring'          => 'https://example.com/security-jobs',
    ],

    /*
    |--------------------------------------------------------------------------
    | Robots.txt Configuration
    |--------------------------------------------------------------------------
    */
    'robots'        => [
        'disallow'    => [
            '/storage/*',
            '/vendor/*',
            '/node_modules/*',
            '/config/*',
            '/backup/*',
            '/database/*',
            '/.env',
            '/.git',
            '/composer.json',
            '/composer.lock',
        ],
        'crawl_delay' => 10,
        'sitemap'     => 'https://example.com/sitemap.xml',
    ],

    /*
    |--------------------------------------------------------------------------
    | Brute Force Protection
    |--------------------------------------------------------------------------
    */
    'brute_force'   => [
        'enabled'          => true,
        'max_attempts'     => 5,
        'lockout_duration' => 900, // 15 minutes
        'monitor_routes'   => [
            '/login',
            '/admin/login',
            '/api/auth/login',
        ],
    ],

    /*
    |--------------------------------------------------------------------------
    | Session Security
    |--------------------------------------------------------------------------
    */
    'session'       => [
        'secure'               => true,
        'http_only'            => true,
        'same_site'            => 'Lax',
        'regenerate_on_login'  => true,
        'regenerate_on_logout' => true,
    ],

    /*
    |--------------------------------------------------------------------------
    | Rate Limiting
    |--------------------------------------------------------------------------
    */
    'rate_limiting' => [
        'enabled'        => true,
        'login_attempts' => [
            'max_attempts'  => 5,
            'decay_minutes' => 15,
        ],
        'api_requests'   => [
            'max_attempts'  => 60,
            'decay_minutes' => 1,
        ],
    ],

    /*
    |--------------------------------------------------------------------------
    | File Upload Security
    |--------------------------------------------------------------------------
    */
    'file_upload'   => [
        'allowed_extensions' => [
            'jpg', 'jpeg', 'png', 'gif', 'pdf', 'doc', 'docx', 'txt',
        ],
        'max_size'           => 10240, // 10MB
        'scan_for_malware'   => false,
        'secure_path'        => 'uploads/',
    ],

    /*
    |--------------------------------------------------------------------------
    | Logging and Monitoring
    |--------------------------------------------------------------------------
    */
    'logging'       => [
        'security_events'     => true,
        'suspicious_activity' => true,
        'failed_logins'       => true,
        'file_access'         => true,
        'rotation'            => [
            'enabled'   => true,
            'max_files' => 30,
            'max_size'  => '100MB',
        ],
    ],

    /*
    |--------------------------------------------------------------------------
    | Audit Configuration
    |--------------------------------------------------------------------------
    */
    'audit'         => [
        'check_permissions'   => true,
        'check_exposed_files' => true,
        'check_headers'       => true,
        'check_env_security'  => true,
        'check_owasp_risks'   => true,
        'generate_report'     => true,
    ],
];
