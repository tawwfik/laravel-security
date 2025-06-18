# Installation Guide

This guide will help you install and set up the Laravel Security Package in your Laravel application.

## Requirements

- **PHP**: 8.0 or higher
- **Laravel**: 9.0 or higher
- **Composer**: Latest version

## Installation

### Step 1: Install via Composer

```bash
composer require tawfik/laravel-security
```

### Step 2: Auto-Discovery (Laravel 5.5+)

The package supports auto-discovery, so the service provider will be registered automatically. No additional configuration is required.

### Step 3: Publish Configuration (Optional)

```bash
php artisan vendor:publish --tag=laravel-security-config
```

This will create `config/laravel-security.php` in your application.

### Step 4: Verify Installation

```bash
php artisan list | grep secure
```

You should see the following commands:
- `secure:all`
- `secure:env`
- `secure:htaccess`
- `secure:security-file`
- `secure:robots`
- `security:audit`

## Manual Installation (Older Laravel Versions)

If you're using Laravel 5.4 or earlier, add the service provider manually:

### Add to config/app.php

```php
'providers' => [
    // ...
    Tawfik\LaravelSecurity\LaravelSecurityServiceProvider::class,
],
```

### Add to composer.json (if needed)

```json
{
    "autoload": {
        "psr-4": {
            "Tawfik\\LaravelSecurity\\": "vendor/tawfik/laravel-security/src/"
        }
    }
}
```

Then run:
```bash
composer dump-autoload
```

## Initial Setup

### Run Basic Security Hardening

```bash
# Run all security commands
php artisan secure:all --backup
```

### Verify Security Configuration

```bash
# Run security audit
php artisan security:audit
```

## Configuration

### Basic Configuration

The package comes with sensible defaults, but you can customize the behavior:

```php
// config/laravel-security.php
return [
    'env' => [
        'backup_before_modify' => true,
        'honeypot_variables' => [
            'FAKE_DB_PASSWORD' => 'honeypot_' . bin2hex(random_bytes(16)),
            'FAKE_API_KEY' => 'honeypot_' . bin2hex(random_bytes(16)),
        ],
        'enforce_production' => true,
    ],
    
    'htaccess' => [
        'security_headers' => [
            'X-Content-Type-Options' => 'nosniff',
            'X-Frame-Options' => 'DENY',
            'X-XSS-Protection' => '1; mode=block',
        ],
        'hsts' => [
            'enabled' => true,
            'max_age' => 31536000,
            'include_subdomains' => true,
        ],
    ],
];
```

## Troubleshooting

### Common Installation Issues

1. **Composer Memory Limit**
   ```bash
   COMPOSER_MEMORY_LIMIT=-1 composer require tawfik/laravel-security
   ```

2. **Permission Issues**
   ```bash
   sudo chown -R $USER:$USER .
   chmod -R 755 storage bootstrap/cache
   ```

3. **Cache Issues**
   ```bash
   php artisan config:clear
   php artisan cache:clear
   composer dump-autoload
   ```

### Verification Commands

```bash
# Check if package is installed
composer show tawfik/laravel-security

# Check if commands are available
php artisan list | grep secure

# Test basic functionality
php artisan secure:env --dry-run
```

## Next Steps

After installation, you can:

1. [Configure the package](Configuration.md)
2. [Run basic security hardening](Basic-Usage.md)
3. [Set up middleware](Middleware/Security-Headers.md)
4. [Learn about advanced features](Advanced/Security-Best-Practices.md)

## Support

If you encounter any issues during installation:

- Check the [Troubleshooting Guide](Advanced/Troubleshooting.md)
- Search [GitHub Issues](https://github.com/tawwfik/laravel-security/issues)
- Start a [Discussion](https://github.com/tawwfik/laravel-security/discussions)
- Email support: `taww002016@gmail.com` 