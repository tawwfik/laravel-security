# Laravel Security Package

## Comprehensive Laravel Security Package

A comprehensive and advanced security package for Laravel 9+ applications running on PHP 8+. This package provides advanced security hardening at the application and server level with zero external dependencies beyond Laravel core.

## Key Features

### 🔒 Advanced Security Commands

- **`secure:env`** - Secure environment file with honeypot variables and remove debug settings
- **`secure:htaccess`** - Generate hardened .htaccess file with security headers
- **`secure:security-file`** - Create RFC 9116 compliant security.txt file
- **`secure:robots`** - Generate secure robots.txt to prevent crawling of sensitive files
- **`secure:all`** - Run all security commands with comprehensive reporting
- **`security:audit`** - Comprehensive security audit and risk assessment

### 🛡️ Advanced Protection

- **Security Headers**: HSTS, CSP, X-Frame-Options, X-XSS-Protection
- **Attack Protection**: CSRF, XSS, SQL Injection, Brute Force
- **Access Control**: Prevent access to sensitive files
- **Security Monitoring**: Log suspicious attempts and alerts
- **Rate Limiting**: Protection against DDoS and automated attacks

## Installation

### Via Composer

```bash
composer require tawfik/laravel-security
```

### Auto-Discovery

The package supports auto-discovery in Laravel 5.5+. The service provider will be registered automatically.

### Manual Installation (Optional)

If you're using an older Laravel version, add the service provider to `config/app.php`:

```php
'providers' => [
    // ...
    Tawfik\LaravelSecurity\LaravelSecurityServiceProvider::class,
],
```

## Usage

### Comprehensive Application Security

```bash
# Run all security commands
php artisan secure:all

# Run in dry-run mode (no actual changes)
php artisan secure:all --dry-run

# Create backups before modifications
php artisan secure:all --backup

# Skip security audit
php artisan secure:all --skip-audit
```

### Secure Environment File

```bash
# Secure .env file
php artisan secure:env

# With backup creation
php artisan secure:env --backup

# In dry-run mode
php artisan secure:env --dry-run
```

**What this command does:**
- Set file permissions to 600 (owner read/write only)
- Add honeypot variables to detect suspicious attempts
- Remove debug variables like `APP_DEBUG=true`
- Enforce `APP_ENV=production`
- Add IP-based access logging

### Generate Hardened .htaccess

```bash
# Generate hardened .htaccess file
php artisan secure:htaccess

# With backup creation
php artisan secure:htaccess --backup
```

**Added Features:**
- Security headers: HSTS, CSP, X-Frame-Options, X-XSS-Protection
- Prevent access to sensitive files (.env, .git, storage/, vendor/)
- Force HTTPS with 301 redirect
- Disable directory listing
- Block suspicious user agents
- File compression and performance optimization

### Create security.txt File

```bash
# Create security.txt file
php artisan secure:security-file

# With custom options
php artisan secure:security-file \
    --contact="mailto:security@example.com" \
    --encryption="https://example.com/pgp-key.txt" \
    --expires="+1 year" \
    --policy="https://example.com/security-policy"
```

**RFC 9116 compliant and includes:**
- Security contact information
- PGP encryption key
- Expiration date
- Policy and acknowledgment links

### Generate Secure robots.txt

```bash
# Generate secure robots.txt
php artisan secure:robots

# With custom options
php artisan secure:robots \
    --sitemap="https://example.com/sitemap.xml" \
    --crawl-delay=10
```

**Prevents crawling of:**
- `/storage/*`, `/vendor/*`, `/node_modules/*`
- `/config/*`, `/backup/*`, `/database/*`
- Sensitive files like `.env`, `.git`

### Comprehensive Security Audit

```bash
# Security audit
php artisan security:audit

# With automatic fixes
php artisan security:audit --fix

# JSON output
php artisan security:audit --output=json

# HTML output
php artisan security:audit --output=html
```

**Tests:**
- File permissions
- Exposed files
- Security headers
- Environment settings
- OWASP Top 10 risks
- Database security
- Session security

## Available Middleware

### Security Headers

```php
// In routes/web.php
Route::middleware(['security.headers'])->group(function () {
    // Application routes
});
```

### Rate Limiting

```php
// Rate limit login attempts
Route::post('/login', [AuthController::class, 'login'])
    ->middleware('security.ratelimit:login');

// Rate limit API requests
Route::middleware(['security.ratelimit:api'])->group(function () {
    // API routes
});
```

### CSRF Protection

```php
// Enhanced CSRF protection
Route::middleware(['security.csrf'])->group(function () {
    // Forms and requests
});
```

## Configuration

### Publish Configuration File

```bash
php artisan vendor:publish --tag=laravel-security-config
```

### Customize Settings

```php
// config/laravel-security.php
return [
    'env' => [
        'backup_before_modify' => true,
        'honeypot_variables' => [
            'FAKE_DB_PASSWORD' => 'honeypot_' . bin2hex(random_bytes(16)),
        ],
        'enforce_production' => true,
    ],
    
    'htaccess' => [
        'security_headers' => [
            'X-Content-Type-Options' => 'nosniff',
            'X-Frame-Options' => 'DENY',
        ],
        'hsts' => [
            'enabled' => true,
            'max_age' => 31536000,
            'include_subdomains' => true,
        ],
    ],
    
    'rate_limiting' => [
        'login_attempts' => [
            'max_attempts' => 5,
            'decay_minutes' => 15,
        ],
    ],
];
```

## Security Best Practices

### 1. Regular Security Audits

```bash
# Add to Cron Jobs
0 2 * * * cd /path/to/your/app && php artisan security:audit --output=json > /var/log/security-audit.log
```

### 2. Monitor Logs

```bash
# Monitor security logs
tail -f storage/logs/laravel.log | grep -i "security\|csrf\|rate.*limit"
```

### 3. Update Dependencies

```bash
# Check for vulnerable dependencies
composer audit

# Update dependencies
composer update
```

### 4. Server Configuration

```apache
# In .htaccess or httpd.conf
<IfModule mod_headers.c>
    Header always set X-Content-Type-Options nosniff
    Header always set X-Frame-Options DENY
    Header always set X-XSS-Protection "1; mode=block"
</IfModule>
```

## CI/CD Integration

### GitHub Actions

```yaml
name: Security Check
on: [push, pull_request]

jobs:
  security:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - name: Setup PHP
        uses: shivammathur/setup-php@v2
        with:
          php-version: '8.1'
      - name: Install dependencies
        run: composer install
      - name: Run security audit
        run: php artisan security:audit --output=json
      - name: Secure application
        run: php artisan secure:all --dry-run
```

### GitLab CI

```yaml
security_check:
  stage: test
  script:
    - composer install
    - php artisan security:audit --output=json
    - php artisan secure:all --dry-run
  artifacts:
    reports:
      junit: security-audit-report.xml
```

## Troubleshooting

### Common Issues

1. **Permission Errors**
   ```bash
   # Fix file permissions
   chmod 600 .env
   chmod 755 storage bootstrap/cache
   ```

2. **HTAccess Errors**
   ```bash
   # Validate .htaccess
   apache2ctl -t
   ```

3. **Configuration Issues**
   ```bash
   # Clear cache
   php artisan config:clear
   php artisan cache:clear
   ```

## Contributing

We welcome contributions! Please follow these steps:

1. Fork the project
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## License

This project is licensed under the MIT License. See the `LICENSE` file for details.

## Support

- **Documentation**: [GitHub Wiki](https://github.com/tawfik/laravel-security/wiki)
- **Issues**: [GitHub Issues](https://github.com/tawfik/laravel-security/issues)
- **Discussions**: [GitHub Discussions](https://github.com/tawfik/laravel-security/discussions)

## Security

If you discover a security vulnerability, please don't open a public issue. Instead, send an email to `security@tawfik.dev`.

## Updates

### Version 1.0.0
- Initial release
- All basic security commands
- Advanced middleware
- Comprehensive security audit
- English documentation

---

**Note**: This package is designed to improve the security of Laravel applications, but it does not guarantee complete security. It's always recommended to follow security best practices and conduct regular security testing. 