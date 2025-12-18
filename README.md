<p align="center">
  <img src="assets/banner-772x250.png" alt="Whitelist XML-RPC">
</p>

# Whitelist XML-RPC

![WordPress](https://img.shields.io/badge/WordPress-5.0%2B-blue?logo=wordpress)
![PHP](https://img.shields.io/badge/PHP-7.4%2B-777BB4?logo=php)
![License](https://img.shields.io/badge/License-GPLv2-green)
![Version](https://img.shields.io/badge/Version-1.2.0-orange)

Automatically whitelists Jetpack server IPs for XML-RPC access, blocking all other `xmlrpc.php` requests with 403 Forbidden.

## Features

- **Automatic IP Sync** - Fetches current Jetpack server IPs daily via WordPress cron
- **Apache + nginx Support** - Auto-detects server type and provides appropriate configuration
- **Native WordPress Integration** - Uses `insert_with_markers()` for safe .htaccess editing (Apache)
- **Admin Dashboard** - View status, logs, whitelisted IPs, and trigger manual syncs
- **Custom IPs** - Add your own IPs or CIDR ranges to the whitelist
- **Configurable Source** - Change the IP source URL if needed
- **Clean Uninstall** - Removes all .htaccess rules and database options

## Why Disable XML-RPC?

XML-RPC (`xmlrpc.php`) is a legacy WordPress feature that has largely been replaced by the REST API since WordPress 4.4 (2015). However, it remains enabled by default and presents significant security risks:

### Security Risks

- **Brute Force Amplification** - Unlike the login page, XML-RPC can test hundreds of username/password combinations in a single request, bypassing rate limiting and security plugins
- **DDoS via Pingback** - Attackers exploit the pingback mechanism to flood sites with requests, overwhelming servers. In 2013, over 2,500 WordPress sites were herded into a botnet this way
- **Attack Proxy** - Your site can be weaponized to attack other sites without your knowledge, using the pingback feature to send malicious requests

### Why Whitelist Instead of Fully Disable?

Many plugins recommend fully disabling XML-RPC, but this breaks **Jetpack** functionality. This plugin takes a smarter approach: block everyone *except* Jetpack's servers, giving you security without sacrificing Jetpack features.

## What Will Stop Working

When this plugin is active, the following features will be blocked for non-whitelisted IPs:

| Feature | Impact | Alternative |
|---------|--------|-------------|
| **WordPress Mobile App** | Won't connect via XML-RPC | Use the REST API (default since WP 4.4) or whitelist your IP |
| **Trackbacks** | Won't receive trackback notifications | Minimal impact - rarely used today |
| **Pingbacks** | Won't receive pingback notifications | Minimal impact - often disabled anyway due to spam |
| **Remote Publishing** | Desktop apps like Windows Live Writer won't work | Use the WordPress admin or whitelist your IP |
| **Older Third-Party Tools** | Some legacy integrations may fail | Most modern tools use REST API instead |

### What Still Works

- ✅ **Jetpack** - All features work (IPs are whitelisted)
- ✅ **REST API** - Completely separate from XML-RPC
- ✅ **WordPress Admin** - Full dashboard access
- ✅ **All Modern Plugins** - REST API-based integrations
- ✅ **Block Editor (Gutenberg)** - Uses REST API
- ✅ **WooCommerce** - Uses REST API

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
| Web Server | Apache 2.4+ or nginx |

### Apache

- `mod_rewrite` enabled
- Writable `.htaccess` file (or use manual copy/paste)

### nginx

- Plugin auto-detects nginx and provides copy/paste configuration
- Manual addition to your `nginx.conf` server block required

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

- **Server Type** - Auto-detected (Apache or nginx)
- **Protection Status** - Real-time verification of rules (Apache) or config reminder (nginx)
- **Last Sync** - When IPs were last updated
- **Whitelisted IPs** - Current count of whitelisted addresses
- **Configuration** - Auto-generated Apache .htaccess or nginx location block
- **Activity Log** - Recent sync activity and any errors

## FAQ

### Will this break my Jetpack connection?

No. The plugin specifically whitelists Jetpack server IPs so Jetpack can continue to communicate with your site.

### Will the WordPress mobile app still work?

It depends. Modern versions of the WordPress app (since 2015) use the REST API by default, which is unaffected by this plugin. If you're having issues, add your phone's IP address to the custom IPs whitelist, or use the Jetpack app instead.

### Can I add my own IPs to the whitelist?

Yes. Use the "Additional Custom IPs" field in the settings to add your own IPs or CIDR ranges (one per line).

### What happens when I deactivate the plugin?

The `.htaccess` rules are automatically removed, restoring normal `xmlrpc.php` access.

### What if .htaccess isn't writable?

The plugin displays manual copy/paste instructions with the exact rules to add to your `.htaccess` file.

### Does this work with nginx?

Yes! The plugin auto-detects nginx and generates a ready-to-use `location` block with all the IP allow/deny rules. Just copy the configuration from the admin panel and add it to your nginx server block, then reload nginx.

## Changelog

### 1.2.0

- Completely redesigned admin settings page
- Modern card-based layout with two-column grid
- Dynamic status hero banner with visual indicators
- Quick stats display with dashicons
- Improved IP grid display (collapsed view for many IPs)
- Enhanced activity log with color-coded messages
- Copy-to-clipboard buttons for configuration code
- Better responsive design for all screen sizes

### 1.1.0

- Added nginx support with auto-detection and config generation
- Server type now displayed in admin panel
- nginx users get copy/paste location block configuration

### 1.0.0

- Initial release
- Automatic Jetpack IP fetching
- WordPress cron scheduling
- Admin settings page with real-time .htaccess verification
- Activity logging
- Custom IP support
- Manual .htaccess fallback for non-writable files

## Privacy

This plugin contacts an external server to fetch IP addresses:

- **Default URL**: `https://jetpack.com/ips-v4.txt`
- **When**: Once daily via WordPress cron, and on manual sync
- **What data is sent**: None - only a standard HTTP GET request
- **What data is received**: A plain text list of IP addresses
- **Why**: To keep the Jetpack server IP whitelist current

You can change the IP source URL in the plugin settings or disable the plugin entirely if you prefer not to make external requests.

No personal data, site information, or tracking data is collected or transmitted.

## License

GPLv2 or later - [gnu.org/licenses/gpl-2.0.html](https://www.gnu.org/licenses/gpl-2.0.html)

## Author

**Gabriel Serafini**
[serafinistudios.com](https://serafinistudios.com)
