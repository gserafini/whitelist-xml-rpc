# Whitelist XML-RPC

![WordPress](https://img.shields.io/badge/WordPress-5.0%2B-blue?logo=wordpress)
![PHP](https://img.shields.io/badge/PHP-7.4%2B-777BB4?logo=php)
![License](https://img.shields.io/badge/License-GPLv2-green)
![Version](https://img.shields.io/badge/Version-1.0.0-orange)

Automatically whitelists Jetpack server IPs for XML-RPC access, blocking all other `xmlrpc.php` requests with 403 Forbidden.

## Features

- **Automatic IP Sync** - Fetches current Jetpack server IPs daily via WordPress cron
- **Native WordPress Integration** - Uses `insert_with_markers()` for safe .htaccess editing
- **Admin Dashboard** - View status, logs, whitelisted IPs, and trigger manual syncs
- **Custom IPs** - Add your own IPs or CIDR ranges to the whitelist
- **Configurable Source** - Change the IP source URL if needed
- **Clean Uninstall** - Removes all .htaccess rules and database options

## How It Works

1. Fetches IP list from `https://jetpack.com/ips-v4.txt` (configurable)
2. Validates each IP address format (IPv4 with optional CIDR)
3. Updates `.htaccess` with Apache `Require ip` directives
4. Blocks all non-whitelisted `xmlrpc.php` requests with `403 Forbidden`
5. Auto-syncs daily via WordPress cron

## Requirements

| Requirement | Version |
|-------------|---------|
| WordPress | 5.0+ |
| PHP | 7.4+ |
| Apache | 2.4+ (uses `Require ip` directive) |
| mod_rewrite | Enabled |
| .htaccess | Writable |

> **Note:** This plugin does not support nginx. For nginx servers, you'll need to configure your `nginx.conf` directly.

## Installation

### From GitHub

```bash
cd /path/to/wordpress/wp-content/plugins/
git clone https://github.com/gserafini/whitelist-xml-rpc.git
```

### Manual Upload

1. Download the latest release
2. Upload the `whitelist-xml-rpc` folder to `/wp-content/plugins/`
3. Activate the plugin through the 'Plugins' menu
4. Go to **Settings > Whitelist XML-RPC** to configure

The plugin automatically syncs IPs on activation.

## Screenshots

### Admin Settings Page

The settings page shows:
- **Protection Status** - Real-time verification that .htaccess rules are in place
- **Last Sync** - When IPs were last updated
- **Whitelisted IPs** - Current count of whitelisted addresses
- **.htaccess Status** - Whether the file is writable
- **Activity Log** - Recent sync activity and any errors

## FAQ

### Will this break my Jetpack connection?

No. The plugin specifically whitelists Jetpack server IPs so Jetpack can continue to communicate with your site.

### Can I add my own IPs to the whitelist?

Yes. Use the "Additional Custom IPs" field in the settings to add your own IPs or CIDR ranges (one per line).

### What happens when I deactivate the plugin?

The `.htaccess` rules are automatically removed, restoring normal `xmlrpc.php` access.

### What if .htaccess isn't writable?

The plugin displays manual copy/paste instructions with the exact rules to add to your `.htaccess` file.

### Does this work with nginx?

No. This plugin uses Apache `.htaccess` rules. For nginx, you would need to configure your `nginx.conf` directly with similar IP allow/deny rules.

## Changelog

### 1.0.0
- Initial release
- Automatic Jetpack IP fetching
- WordPress cron scheduling
- Admin settings page with real-time .htaccess verification
- Activity logging
- Custom IP support
- Manual .htaccess fallback for non-writable files

## License

GPLv2 or later - https://www.gnu.org/licenses/gpl-2.0.html

## Author

**Gabriel Serafini**
[serafinistudios.com](https://serafinistudios.com)
