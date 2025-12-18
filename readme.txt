=== Whitelist XML-RPC ===
Contributors: gserafini
Tags: security, xmlrpc, jetpack, whitelist, firewall
Requires at least: 5.0
Tested up to: 6.7
Requires PHP: 7.4
Stable tag: 1.1.0
License: GPLv2 or later
License URI: https://www.gnu.org/licenses/gpl-2.0.html

Automatically whitelists Jetpack server IPs for XML-RPC access, blocking all other xmlrpc.php requests. Supports both Apache and nginx.

== Description ==

Whitelist XML-RPC protects your WordPress site by restricting xmlrpc.php access to only authorized IP addresses (Jetpack servers by default).

**Why Disable XML-RPC?**

XML-RPC (xmlrpc.php) is a legacy WordPress feature largely replaced by the REST API since WordPress 4.4 (2015). It remains enabled by default but presents significant security risks:

* **Brute Force Amplification** - XML-RPC can test hundreds of passwords in a single request, bypassing rate limiting
* **DDoS via Pingback** - Attackers exploit pingbacks to flood sites with requests
* **Attack Proxy** - Your site can be weaponized to attack others via the pingback feature

This plugin takes a smarter approach than fully disabling XML-RPC: block everyone *except* Jetpack's servers, giving you security without sacrificing Jetpack features.

**What Will Stop Working:**

* WordPress mobile app (XML-RPC mode) - Use REST API mode or whitelist your IP
* Trackbacks from other sites - Rarely used today
* Pingbacks from other sites - Often disabled anyway due to spam
* Remote publishing via desktop apps - Use admin dashboard instead
* Some legacy third-party integrations - Most modern tools use REST API

**What Still Works:**

* Jetpack - All features (IPs are whitelisted)
* REST API - Completely separate from XML-RPC
* WordPress Admin - Full dashboard access
* Block Editor (Gutenberg) - Uses REST API
* WooCommerce - Uses REST API
* All modern plugins - REST API-based integrations

**Features:**

* Automatically fetches current Jetpack server IPs daily
* Supports both Apache and nginx (auto-detected)
* Uses WordPress cron for scheduled updates
* Uses WordPress's native .htaccess editing for Apache (insert_with_markers)
* Generates ready-to-use nginx configuration blocks
* Admin dashboard with status, logs, and manual sync
* Support for custom additional IPs
* Configurable IP source URL
* Clean uninstall - removes all .htaccess rules and options

**How It Works:**

1. Fetches IP list from https://jetpack.com/ips-v4.txt (configurable)
2. Validates each IP address format
3. Auto-detects your web server (Apache or nginx)
4. Apache: Updates .htaccess with Require ip directives
5. nginx: Generates location block for manual configuration
6. Blocks all non-whitelisted xmlrpc.php requests with 403 Forbidden
7. Syncs automatically once per day via WordPress cron

**Requirements:**

* Apache 2.4+ with mod_rewrite enabled, OR
* nginx (plugin provides copy/paste configuration)
* WordPress 5.0+
* PHP 7.4+

== Installation ==

1. Upload the `whitelist-xml-rpc` folder to `/wp-content/plugins/`
2. Activate the plugin through the 'Plugins' menu
3. Go to Settings > Whitelist XML-RPC to configure
4. The plugin automatically syncs IPs on activation

**For nginx users:**
After activation, go to the settings page and copy the generated nginx configuration into your server block, then reload nginx.

== Frequently Asked Questions ==

= Will this break my Jetpack connection? =

No. The plugin specifically whitelists Jetpack server IPs so Jetpack can continue to communicate with your site.

= Will the WordPress mobile app still work? =

It depends. Modern versions of the WordPress app (since 2015) use the REST API by default, which is unaffected. If you're having issues, add your phone's IP to the custom whitelist, or use the Jetpack app.

= Can I add my own IPs to the whitelist? =

Yes. Use the "Additional Custom IPs" field in the settings to add your own IPs or CIDR ranges.

= What happens when I deactivate the plugin? =

The .htaccess rules are automatically removed (Apache), restoring normal xmlrpc.php access. nginx users will need to manually remove the location block.

= Does this work with nginx? =

Yes! The plugin auto-detects nginx and generates a ready-to-use location block with all the IP allow/deny rules. Just copy the configuration from the admin panel and add it to your nginx server block.

== Privacy ==

This plugin contacts an external server to fetch IP addresses:

* **Default URL**: `https://jetpack.com/ips-v4.txt`
* **When**: Once daily via WordPress cron, and on manual sync
* **What data is sent**: None - only a standard HTTP GET request
* **What data is received**: A plain text list of IP addresses
* **Why**: To keep the Jetpack server IP whitelist current

You can change the IP source URL in the plugin settings or disable the plugin entirely if you prefer not to make external requests.

No personal data, site information, or tracking data is collected or transmitted by this plugin.

== Changelog ==

= 1.1.0 =
* Added nginx support with auto-detection
* Server type now displayed in admin panel
* nginx users get copy/paste location block configuration
* Improved status display for different server types

= 1.0.0 =
* Initial release
* Automatic Jetpack IP fetching
* WordPress cron scheduling
* Admin settings page
* Activity logging
* Custom IP support
* Manual .htaccess fallback for non-writable files

== Upgrade Notice ==

= 1.1.0 =
Added nginx support! The plugin now auto-detects your server type and provides appropriate configuration.

= 1.0.0 =
Initial release.
