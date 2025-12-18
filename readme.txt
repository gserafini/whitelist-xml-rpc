=== Whitelist XML-RPC ===
Contributors: gserafini
Tags: security, xmlrpc, jetpack, whitelist, firewall
Requires at least: 5.0
Tested up to: 6.4
Requires PHP: 7.4
Stable tag: 1.0.0
License: GPLv2 or later
License URI: https://www.gnu.org/licenses/gpl-2.0.html

Automatically whitelists Jetpack server IPs for XML-RPC access, blocking all other xmlrpc.php requests.

== Description ==

Whitelist XML-RPC protects your WordPress site by restricting xmlrpc.php access to only authorized IP addresses (Jetpack servers by default).

**Features:**

* Automatically fetches current Jetpack server IPs daily
* Uses WordPress cron for scheduled updates
* Uses WordPress's native .htaccess editing (insert_with_markers)
* Admin dashboard with status, logs, and manual sync
* Support for custom additional IPs
* Configurable IP source URL
* Clean uninstall - removes all .htaccess rules and options

**How It Works:**

1. Fetches IP list from https://jetpack.com/ips-v4.txt (configurable)
2. Validates each IP address format
3. Updates .htaccess with Apache Require ip directives
4. Blocks all non-whitelisted xmlrpc.php requests with 403 Forbidden
5. Syncs automatically once per day via WordPress cron

**Requirements:**

* Apache web server with mod_rewrite enabled
* Apache 2.4+ (uses Require ip directive)
* Writable .htaccess file

== Installation ==

1. Upload the `whitelist-xml-rpc` folder to `/wp-content/plugins/`
2. Activate the plugin through the 'Plugins' menu
3. Go to Settings > XML-RPC Whitelist to configure
4. The plugin automatically syncs IPs on activation

== Frequently Asked Questions ==

= Will this break my Jetpack connection? =

No. The plugin specifically whitelists Jetpack server IPs so Jetpack can continue to communicate with your site.

= Can I add my own IPs to the whitelist? =

Yes. Use the "Additional Custom IPs" field in the settings to add your own IPs or CIDR ranges.

= What happens when I deactivate the plugin? =

The .htaccess rules are automatically removed, restoring normal xmlrpc.php access.

= Does this work with nginx? =

No. This plugin uses Apache .htaccess rules. For nginx, you would need to configure your nginx.conf directly.

== Changelog ==

= 1.0.0 =
* Initial release
* Automatic Jetpack IP fetching
* WordPress cron scheduling
* Admin settings page
* Activity logging
* Custom IP support

== Upgrade Notice ==

= 1.0.0 =
Initial release.
