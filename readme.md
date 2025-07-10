# Two Factor WordPress for MemberPress

A WordPress plugin that provides two-factor authentication integration specifically designed for MemberPress. This plugin is forked from the official WordPress Two-Factor plugin and enhanced to work seamlessly with MemberPress membership sites.

## Features

- **Force 2FA Setup**: All users are required to set up two-factor authentication on their first login after plugin activation
- **Frontend Integration**: 2FA setup and login happens on the frontend, integrating with MemberPress login flow
- **TOTP Priority**: Time-based One-Time Password (Authenticator apps) is the default and recommended method
- **Multiple Authentication Methods**: Support for TOTP, Email, FIDO U2F, and backup codes
- **Admin Controls**: Administrators can manage which authentication methods are allowed
- **Role-based Requirements**: Option to require 2FA for specific user roles only
- **Backup Codes**: Users can generate and download backup codes for account recovery
- **MemberPress Integration**: Respects MemberPress redirect URLs and login flow

## Installation

1. Upload the plugin files to `/wp-content/plugins/two-factor-wp-memberpress/`
2. Activate the plugin through the 'Plugins' screen in WordPress
3. Go to Settings > Two Factor MP to configure the plugin

## Configuration

### Admin Settings

Navigate to **Settings > Two Factor MP** in your WordPress admin to configure:

- **Force Two-Factor Authentication**: Enable to require all users to set up 2FA
- **Required User Roles**: Select which user roles must use 2FA (leave empty for all users)
- **Allowed Authentication Methods**: Choose which 2FA methods users can use

### Forcing 2FA for Existing Users

Use the "Force 2FA Setup for All Users" button in the admin settings to mark all existing users as needing to set up 2FA on their next login.

## Usage

### For Users

#### First-time Setup

1. After the plugin is activated, users will be redirected to a 2FA setup page on their next login
2. Users will be guided through:
   - Installing an authenticator app (Google Authenticator, Microsoft Authenticator, Authy)
   - Scanning a QR code or entering a secret key
   - Verifying the setup with a test code
   - Downloading backup codes

#### Daily Login

1. Enter username and password as normal
2. Enter the 6-digit code from their authenticator app
3. Alternative options:
   - Use email 2FA (if enabled)
   - Use a backup code
   - Switch to another enabled authentication method

### For Developers

#### Shortcode

Use the `[two_factor_setup]` shortcode to display a 2FA setup interface on any page.

#### Hooks and Filters

The plugin provides several hooks for customization:

```php
// Filter available providers
add_filter( 'two_factor_providers', 'your_custom_provider_filter' );

// Customize post-login redirect
add_filter( 'two_factor_memberpress_redirect_url', 'your_redirect_function' );
```

## Supported Authentication Methods

### TOTP (Time-based One-Time Password) - Default
- **Apps**: Google Authenticator, Microsoft Authenticator, Authy
- **Security**: High
- **Offline**: Works without internet connection

### Email
- **Method**: Codes sent to user's email address
- **Security**: Medium (depends on email security)
- **Backup**: Good fallback option

### FIDO U2F
- **Method**: Hardware security keys (YubiKey, etc.)
- **Security**: Very High
- **Requirements**: HTTPS and compatible browser

### Backup Codes
- **Method**: Pre-generated single-use codes
- **Purpose**: Account recovery when primary method is unavailable
- **Important**: Each code can only be used once

## Requirements

- WordPress 6.7 or higher
- PHP 7.2 or higher
- MemberPress plugin (recommended)
- HTTPS (required for FIDO U2F)

## Compatibility

- **WordPress**: 6.7+
- **MemberPress**: All versions
- **Browsers**: All modern browsers
- **Mobile**: Responsive design works on all devices

## Security Best Practices

1. **HTTPS**: Always use HTTPS in production
2. **Backup Codes**: Encourage users to save backup codes securely
3. **Email Security**: If using email 2FA, ensure email accounts are secure
4. **Regular Audits**: Review user 2FA status regularly

## Troubleshooting

### Users Can't Complete Setup

- Check that the site time is correct (important for TOTP)
- Verify QR codes are displaying properly
- Ensure users are using compatible authenticator apps

### Login Issues

- Verify the user's device time is synchronized
- Check that backup codes haven't all been used
- Confirm the user is entering codes correctly (no spaces)

### Plugin Conflicts

- Deactivate other 2FA plugins to avoid conflicts
- Check that caching plugins aren't interfering with sessions
- Ensure no other plugins are modifying the login flow

## Support

For support and feature requests, please use the GitHub repository:
https://github.com/pjwilson1977/two-factor-wp-memberpress

## Changelog

### 0.14.0-mp.1
- Initial MemberPress integration release
- Frontend 2FA setup and login
- TOTP as default authentication method
- Admin controls for method management
- Role-based 2FA requirements
- Backup code generation
- Responsive design templates

## Credits

This plugin is based on the official WordPress Two-Factor plugin by WordPress.org Contributors.

## License

GPL-2.0-or-later

Please privately report any potential security issues to the [WordPress HackerOne](https://hackerone.com/wordpress) program.
