# URL Prefix Configuration

## Overview
The Visitor Management System now supports configurable URL prefixes through the `.env` file. This allows you to easily change the base URL path without modifying any code.

## Configuration

### In `.env` file:
```env
# URL Configuration
URL_PREFIX=/vms
```

### Default Value:
- `/vms` (if not specified)

## Usage Examples

### Default (vms):
```
URL_PREFIX=/vms
Access URL: http://localhost:5001/vms
```

### Custom prefix:
```
URL_PREFIX=/visitor-management
Access URL: http://localhost:5001/visitor-management
```

### Root path:
```
URL_PREFIX=/
Access URL: http://localhost:5001/
```

## How It Works

1. **Route Decorators**: All Flask routes now use `get_url_prefix()` function to dynamically construct URLs
2. **Static Files**: Static file paths are automatically adjusted to include the prefix
3. **Application Root**: Flask's `APPLICATION_ROOT` is set to handle URL generation correctly
4. **Redirects**: All `url_for()` calls automatically respect the configured prefix

## Implementation Details

### Route Definition Example:
```python
# Before (hardcoded)
@app.route('/vms/login')

# After (dynamic)
@app.route(get_url_prefix() + '/login')
```

### Helper Function:
```python
def get_url_prefix():
    return app.config.get('URL_PREFIX', '/vms')
```

## Benefits

1. **Easy Configuration**: Change URL structure by editing one line in `.env`
2. **No Code Changes**: No need to modify route decorators when changing prefixes
3. **Consistent URLs**: All URLs automatically update when prefix changes
4. **Deployment Flexibility**: Easy to deploy under different URL paths

## Note
After changing the `URL_PREFIX` in `.env`, you need to restart the application for changes to take effect.