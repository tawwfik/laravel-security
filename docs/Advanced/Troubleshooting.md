# Troubleshooting Guide

This guide helps you resolve common issues with the Laravel Security Package.

## Common Issues

### 1. Command Not Found

**Problem**: `php artisan secure:all` returns "Command not found"

**Solutions**:
```bash
# Clear cache and reload
php artisan config:clear
php artisan cache:clear
composer dump-autoload

# Check if package is installed
composer show tawfik/laravel-security

# Verify commands are available
php artisan list | grep secure
```

### 2. Permission Errors

**Problem**: "Permission denied" when running security commands

**Solutions**:
```bash
# Fix file permissions
chmod 600 .env
chmod 755 storage bootstrap/cache
chown -R www-data:www-data storage bootstrap/cache

# For development
chmod -R 755 storage bootstrap/cache
```

### 3. Backup Creation Fails

**Problem**: Backup files are not created

**Solutions**:
```bash
# Check disk space
df -h

# Check write permissions
ls -la .env*

# Create backup manually
cp .env .env.backup.$(date +%Y-%m-%d-%H-%M-%S)
```

### 4. HTAccess Errors

**Problem**: Apache errors after generating .htaccess

**Solutions**:
```bash
# Validate .htaccess syntax
apache2ctl -t

# Check Apache error logs
tail -f /var/log/apache2/error.log

# Test with dry-run first
php artisan secure:htaccess --dry-run
```

### 5. Security Audit Fails

**Problem**: Security audit command crashes

**Solutions**:
```bash
# Run with verbose output
php artisan security:audit --detailed

# Check PHP memory limit
php -i | grep memory_limit

# Increase memory limit temporarily
php -d memory_limit=512M artisan security:audit
```

## Error Messages and Solutions

### "Call to a member function setOption() on null"

**Cause**: Command input handling issue

**Solution**: Update to latest version
```bash
composer update tawfik/laravel-security
```

### "The 'verbose' option does not exist"

**Cause**: Option conflict with Laravel's built-in options

**Solution**: Use `--detailed` instead of `--verbose`
```bash
php artisan security:audit --detailed
```

### "decoct(): Argument #1 ($num) must be of type int"

**Cause**: File permissions check issue

**Solution**: Update to latest version
```bash
composer update tawfik/laravel-security
```

## Performance Issues

### Slow Command Execution

**Solutions**:
```bash
# Clear all caches
php artisan optimize:clear

# Check for large files
find . -size +10M

# Monitor system resources
htop
```

### Memory Issues

**Solutions**:
```bash
# Increase PHP memory limit
php -d memory_limit=1G artisan secure:all

# Check current memory usage
php -i | grep memory_limit
```

## Configuration Issues

### Configuration Not Loading

**Solutions**:
```bash
# Publish configuration
php artisan vendor:publish --tag=laravel-security-config

# Clear configuration cache
php artisan config:clear

# Check configuration file
cat config/laravel-security.php
```

### Custom Configuration Not Working

**Solutions**:
```bash
# Verify configuration structure
php artisan tinker
>>> config('laravel-security')

# Check for syntax errors
php -l config/laravel-security.php
```

## Server-Specific Issues

### Apache Issues

**Common Problems**:
- mod_rewrite not enabled
- .htaccess not allowed
- Directory permissions

**Solutions**:
```bash
# Enable mod_rewrite
sudo a2enmod rewrite
sudo systemctl restart apache2

# Check .htaccess is allowed
grep -r "AllowOverride" /etc/apache2/
```

### Nginx Issues

**Note**: This package is primarily designed for Apache. For Nginx:

1. Convert .htaccess rules to nginx.conf
2. Use Laravel's built-in security features
3. Consider using a reverse proxy

### Shared Hosting Issues

**Common Problems**:
- Limited file permissions
- No SSH access
- Restricted commands

**Solutions**:
1. Contact your hosting provider
2. Use web-based file manager
3. Request SSH access if needed

## Debugging Commands

### Verbose Output

```bash
# Run commands with detailed output
php artisan secure:all --detailed

# Check command options
php artisan help secure:all
```

### Log Analysis

```bash
# Check Laravel logs
tail -f storage/logs/laravel.log

# Check system logs
tail -f /var/log/syslog

# Check Apache logs
tail -f /var/log/apache2/access.log
```

### System Information

```bash
# Check PHP version
php -v

# Check Laravel version
php artisan --version

# Check package version
composer show tawfik/laravel-security
```

## Getting Help

If you can't resolve an issue:

1. **Search existing issues**: [GitHub Issues](https://github.com/tawfik/laravel-security/issues)
2. **Check discussions**: [GitHub Discussions](https://github.com/tawfik/laravel-security/discussions)
3. **Create a new issue** with:
   - Laravel version
   - PHP version
   - Package version
   - Error message
   - Steps to reproduce
   - Expected vs actual behavior

## Emergency Recovery

If something goes wrong:

```bash
# Restore from backup
cp .env.backup.* .env

# Restore .htaccess
cp public/.htaccess.backup.* public/.htaccess

# Clear all caches
php artisan optimize:clear

# Reinstall package
composer remove tawfik/laravel-security
composer require tawfik/laravel-security
```

## Prevention

To avoid issues:

1. **Always use `--backup`** when running commands
2. **Test in development** before production
3. **Use `--dry-run`** to preview changes
4. **Keep backups** of important files
5. **Monitor logs** regularly
6. **Update regularly** to latest version 