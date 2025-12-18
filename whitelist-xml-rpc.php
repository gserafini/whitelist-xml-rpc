<?php
/**
 * Plugin Name: Whitelist XML-RPC
 * Plugin URI: https://github.com/gserafini/whitelist-xml-rpc
 * Description: Automatically whitelists Jetpack server IPs for XML-RPC access, blocking all other xmlrpc.php requests with 403 Forbidden. Syncs daily via WordPress cron.
 * Version: 1.2.0
 * Author: Gabriel Serafini
 * Author URI: https://serafinistudios.com
 * License: GPL v2 or later
 * License URI: https://www.gnu.org/licenses/gpl-2.0.html
 * Text Domain: whitelist-xml-rpc
 * Requires at least: 5.0
 * Requires PHP: 7.4
 */

// Prevent direct access
if ( ! defined( 'ABSPATH' ) ) {
    exit;
}

class XMLRPC_IP_Whitelist {

    const VERSION = '1.1.0';
    const OPTION_PREFIX = 'xmlrpc_whitelist_';
    const CRON_HOOK = 'xmlrpc_whitelist_sync';
    const HTACCESS_MARKER = 'Whitelist XML-RPC';
    const DEFAULT_IP_SOURCE = 'https://jetpack.com/ips-v4.txt';
    const CACHE_KEY = 'xmlrpc_whitelist_cached_ips';
    const CACHE_EXPIRY = HOUR_IN_SECONDS;

    /**
     * Initialize the plugin
     */
    public static function init() {
        // Admin hooks
        add_action( 'admin_menu', array( __CLASS__, 'add_admin_menu' ) );
        add_action( 'admin_init', array( __CLASS__, 'register_settings' ) );
        add_action( 'admin_notices', array( __CLASS__, 'admin_notices' ) );

        // Cron hook
        add_action( self::CRON_HOOK, array( __CLASS__, 'sync_ips' ) );

        // Activation/deactivation
        register_activation_hook( __FILE__, array( __CLASS__, 'activate' ) );
        register_deactivation_hook( __FILE__, array( __CLASS__, 'deactivate' ) );

        // Handle manual sync action
        add_action( 'admin_post_xmlrpc_whitelist_sync', array( __CLASS__, 'handle_manual_sync' ) );
    }

    /**
     * Plugin activation
     */
    public static function activate() {
        // Set default options
        if ( get_option( self::OPTION_PREFIX . 'enabled' ) === false ) {
            update_option( self::OPTION_PREFIX . 'enabled', '1' );
        }
        if ( get_option( self::OPTION_PREFIX . 'ip_source' ) === false ) {
            update_option( self::OPTION_PREFIX . 'ip_source', self::DEFAULT_IP_SOURCE );
        }

        // Schedule cron if enabled
        if ( get_option( self::OPTION_PREFIX . 'enabled' ) === '1' ) {
            self::schedule_cron();
        }

        // Run initial sync
        self::sync_ips();
    }

    /**
     * Plugin deactivation
     */
    public static function deactivate() {
        // Clear cron
        self::clear_cron();

        // Remove .htaccess rules
        self::remove_htaccess_rules();
    }

    /**
     * Schedule the daily cron job
     */
    public static function schedule_cron() {
        if ( ! wp_next_scheduled( self::CRON_HOOK ) ) {
            wp_schedule_event( time(), 'daily', self::CRON_HOOK );
        }
    }

    /**
     * Clear the cron job
     */
    public static function clear_cron() {
        $timestamp = wp_next_scheduled( self::CRON_HOOK );
        if ( $timestamp ) {
            wp_unschedule_event( $timestamp, self::CRON_HOOK );
        }
    }

    /**
     * Add admin menu page
     */
    public static function add_admin_menu() {
        add_options_page(
            __( 'Whitelist XML-RPC', 'whitelist-xml-rpc' ),
            __( 'Whitelist XML-RPC', 'whitelist-xml-rpc' ),
            'manage_options',
            'whitelist-xml-rpc',
            array( __CLASS__, 'render_settings_page' )
        );
    }

    /**
     * Register settings
     */
    public static function register_settings() {
        register_setting( 'xmlrpc_whitelist_settings', self::OPTION_PREFIX . 'enabled', array(
            'type' => 'string',
            'sanitize_callback' => 'sanitize_text_field',
            'default' => '1',
        ) );

        register_setting( 'xmlrpc_whitelist_settings', self::OPTION_PREFIX . 'ip_source', array(
            'type' => 'string',
            'sanitize_callback' => 'esc_url_raw',
            'default' => self::DEFAULT_IP_SOURCE,
        ) );

        register_setting( 'xmlrpc_whitelist_settings', self::OPTION_PREFIX . 'custom_ips', array(
            'type' => 'string',
            'sanitize_callback' => array( __CLASS__, 'sanitize_custom_ips' ),
            'default' => '',
        ) );
    }

    /**
     * Sanitize custom IPs input
     */
    public static function sanitize_custom_ips( $input ) {
        if ( empty( $input ) ) {
            return '';
        }

        $lines = explode( "\n", $input );
        $valid_ips = array();

        foreach ( $lines as $line ) {
            $ip = trim( $line );
            if ( empty( $ip ) || strpos( $ip, '#' ) === 0 ) {
                continue;
            }
            if ( self::validate_ip( $ip ) ) {
                $valid_ips[] = $ip;
            }
        }

        return implode( "\n", $valid_ips );
    }

    /**
     * Validate IP format (IPv4 with optional CIDR)
     * Uses PHP's filter_var() for robust validation
     */
    public static function validate_ip( $ip ) {
        // Handle null/empty input (PHP 8.4+ deprecates null to explode)
        if ( $ip === null || $ip === '' ) {
            return false;
        }

        // Split IP and optional CIDR
        $parts = explode( '/', $ip, 2 );
        $ip_only = $parts[0];

        // Use PHP's built-in filter_var for robust IP validation
        if ( ! filter_var( $ip_only, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4 ) ) {
            return false;
        }

        // Validate CIDR if present
        if ( isset( $parts[1] ) ) {
            $cidr = $parts[1];
            // Must be numeric and between 0-32
            if ( ! ctype_digit( $cidr ) ) {
                return false;
            }
            $cidr_int = (int) $cidr;
            if ( $cidr_int < 0 || $cidr_int > 32 ) {
                return false;
            }
        }

        return true;
    }

    /**
     * Fetch IPs from remote source
     */
    public static function fetch_remote_ips() {
        $source_url = get_option( self::OPTION_PREFIX . 'ip_source', self::DEFAULT_IP_SOURCE );

        $response = wp_remote_get( $source_url, array(
            'timeout' => 30,
            'sslverify' => true,
        ) );

        if ( is_wp_error( $response ) ) {
            self::log( 'ERROR: Failed to fetch IPs - ' . $response->get_error_message() );
            return false;
        }

        $code = wp_remote_retrieve_response_code( $response );
        if ( $code !== 200 ) {
            self::log( 'ERROR: IP source returned HTTP ' . $code );
            return false;
        }

        $body = wp_remote_retrieve_body( $response );
        if ( empty( $body ) ) {
            self::log( 'ERROR: Empty response from IP source' );
            return false;
        }

        // Parse and validate IPs
        $lines = explode( "\n", $body );
        $valid_ips = array();
        $invalid_count = 0;

        foreach ( $lines as $line ) {
            $ip = trim( $line );
            if ( empty( $ip ) || strpos( $ip, '#' ) === 0 ) {
                continue;
            }
            if ( self::validate_ip( $ip ) ) {
                $valid_ips[] = $ip;
            } else {
                $invalid_count++;
                self::log( 'WARNING: Skipping invalid IP: ' . $ip );
            }
        }

        // Sanity check
        if ( count( $valid_ips ) < 3 ) {
            self::log( 'ERROR: Too few valid IPs (' . count( $valid_ips ) . ') - aborting' );
            return false;
        }

        if ( $invalid_count > 3 ) {
            self::log( 'ERROR: Too many invalid IPs (' . $invalid_count . ') - possible data corruption' );
            return false;
        }

        return $valid_ips;
    }

    /**
     * Get all IPs (remote + custom)
     */
    public static function get_all_ips() {
        $ips = array();

        // Fetch remote IPs
        $remote_ips = self::fetch_remote_ips();
        if ( $remote_ips ) {
            $ips = array_merge( $ips, $remote_ips );
        }

        // Add custom IPs
        $custom_ips = get_option( self::OPTION_PREFIX . 'custom_ips', '' );
        if ( ! empty( $custom_ips ) ) {
            $custom_lines = explode( "\n", $custom_ips );
            foreach ( $custom_lines as $ip ) {
                $ip = trim( $ip );
                if ( ! empty( $ip ) && self::validate_ip( $ip ) ) {
                    $ips[] = $ip;
                }
            }
        }

        return array_unique( $ips );
    }

    /**
     * Get cached IPs for display (avoids remote fetch on page load)
     * Falls back to last synced IPs if cache is empty
     */
    public static function get_cached_ips_for_display() {
        // Try transient cache first (set during sync)
        $cached = get_transient( self::CACHE_KEY );
        if ( false !== $cached && is_array( $cached ) ) {
            return $cached;
        }

        // Fall back to custom IPs only (no remote fetch)
        $ips = array();
        $custom_ips = get_option( self::OPTION_PREFIX . 'custom_ips', '' );
        if ( ! empty( $custom_ips ) ) {
            $custom_lines = explode( "\n", $custom_ips );
            foreach ( $custom_lines as $ip ) {
                $ip = trim( $ip );
                if ( ! empty( $ip ) && self::validate_ip( $ip ) ) {
                    $ips[] = $ip;
                }
            }
        }

        // Return whatever we have, with note about cache miss
        return $ips;
    }

    /**
     * Generate .htaccess rules
     */
    public static function generate_htaccess_rules( $ips ) {
        if ( empty( $ips ) ) {
            return array();
        }

        $rules = array();
        $rules[] = '# Whitelist IPs for xmlrpc.php access';
        $rules[] = '# Source: ' . get_option( self::OPTION_PREFIX . 'ip_source', self::DEFAULT_IP_SOURCE );
        $rules[] = '# Last updated: ' . current_time( 'Y-m-d H:i:s' );
        $rules[] = '<Files "xmlrpc.php">';
        $rules[] = '    <RequireAny>';

        foreach ( $ips as $ip ) {
            $rules[] = '        Require ip ' . $ip;
        }

        $rules[] = '    </RequireAny>';
        $rules[] = '    ErrorDocument 403 "Forbidden"';
        $rules[] = '</Files>';

        return $rules;
    }

    /**
     * Update .htaccess with whitelist rules
     */
    public static function update_htaccess( $ips ) {
        // Require the file functions
        if ( ! function_exists( 'insert_with_markers' ) ) {
            require_once ABSPATH . 'wp-admin/includes/misc.php';
        }

        $htaccess_file = self::get_htaccess_path();

        if ( ! $htaccess_file ) {
            self::log( 'ERROR: Could not determine .htaccess path' );
            return false;
        }

        if ( ! file_exists( $htaccess_file ) ) {
            self::log( 'ERROR: .htaccess file not found at ' . $htaccess_file );
            return false;
        }

        if ( ! is_writable( $htaccess_file ) ) {
            self::log( 'ERROR: .htaccess is not writable' );
            return false;
        }

        $rules = self::generate_htaccess_rules( $ips );

        // Use WordPress's built-in function to insert with markers
        $result = insert_with_markers( $htaccess_file, self::HTACCESS_MARKER, $rules );

        if ( $result ) {
            self::log( 'Successfully updated .htaccess with ' . count( $ips ) . ' IPs' );
            update_option( self::OPTION_PREFIX . 'last_sync', current_time( 'timestamp' ) );
            update_option( self::OPTION_PREFIX . 'last_ip_count', count( $ips ) );
            update_option( self::OPTION_PREFIX . 'last_status', 'success' );
        } else {
            self::log( 'ERROR: Failed to update .htaccess' );
            update_option( self::OPTION_PREFIX . 'last_status', 'error' );
        }

        return $result;
    }

    /**
     * Remove .htaccess rules
     */
    public static function remove_htaccess_rules() {
        if ( ! function_exists( 'insert_with_markers' ) ) {
            require_once ABSPATH . 'wp-admin/includes/misc.php';
        }

        $htaccess_file = self::get_htaccess_path();
        if ( $htaccess_file && file_exists( $htaccess_file ) && is_writable( $htaccess_file ) ) {
            insert_with_markers( $htaccess_file, self::HTACCESS_MARKER, array() );
            self::log( 'Removed .htaccess rules (plugin deactivated)' );
        }
    }

    /**
     * Get .htaccess file path
     */
    public static function get_htaccess_path() {
        if ( ! function_exists( 'get_home_path' ) ) {
            require_once ABSPATH . 'wp-admin/includes/file.php';
        }

        $home_path = get_home_path();
        return $home_path . '.htaccess';
    }

    /**
     * Check if .htaccess is writable
     */
    public static function is_htaccess_writable() {
        $htaccess_file = self::get_htaccess_path();
        return $htaccess_file && file_exists( $htaccess_file ) && is_writable( $htaccess_file );
    }

    /**
     * Detect if server is running nginx
     */
    public static function is_nginx() {
        // Check SERVER_SOFTWARE
        if ( isset( $_SERVER['SERVER_SOFTWARE'] ) && stripos( $_SERVER['SERVER_SOFTWARE'], 'nginx' ) !== false ) {
            return true;
        }

        // Check for nginx-specific server variables
        if ( isset( $_SERVER['NGINX_VERSION'] ) ) {
            return true;
        }

        // Check if .htaccess doesn't exist (common on nginx)
        $htaccess_file = self::get_htaccess_path();
        if ( $htaccess_file && ! file_exists( $htaccess_file ) ) {
            // Could be nginx, but also could be fresh Apache install
            // Only return true if we have other indicators
            return false;
        }

        return false;
    }

    /**
     * Generate nginx configuration rules
     */
    public static function generate_nginx_rules( $ips ) {
        if ( empty( $ips ) ) {
            return '';
        }

        $source_url = get_option( self::OPTION_PREFIX . 'ip_source', self::DEFAULT_IP_SOURCE );
        $output = "# Whitelist XML-RPC for nginx\n";
        $output .= "# Source: {$source_url}\n";
        $output .= "# Last updated: " . current_time( 'Y-m-d H:i:s' ) . "\n";
        $output .= "# Add this to your server block in nginx.conf\n\n";
        $output .= "location = /xmlrpc.php {\n";

        foreach ( $ips as $ip ) {
            $output .= "    allow {$ip};\n";
        }

        $output .= "    deny all;\n\n";
        $output .= "    # Pass to PHP-FPM if allowed (adjust socket path as needed)\n";
        $output .= "    include fastcgi_params;\n";
        $output .= "    fastcgi_param SCRIPT_FILENAME \$document_root\$fastcgi_script_name;\n";
        $output .= "    fastcgi_pass unix:/var/run/php-fpm.sock;\n";
        $output .= "}\n";

        return $output;
    }

    /**
     * Verify that .htaccess actually contains our rules
     * Only call this on admin page load, not on every request
     */
    public static function verify_htaccess_rules() {
        $htaccess_file = self::get_htaccess_path();

        if ( ! $htaccess_file || ! file_exists( $htaccess_file ) ) {
            return false;
        }

        // phpcs:ignore WordPress.WP.AlternativeFunctions.file_get_contents_file_get_contents
        $contents = file_get_contents( $htaccess_file );
        if ( false === $contents ) {
            return false;
        }

        $marker = self::HTACCESS_MARKER;
        $begin_marker = "# BEGIN {$marker}";
        $end_marker = "# END {$marker}";

        // Check both markers exist
        return ( strpos( $contents, $begin_marker ) !== false && strpos( $contents, $end_marker ) !== false );
    }

    /**
     * Get manual .htaccess rules for copy/paste
     */
    public static function get_manual_htaccess_rules() {
        $ips = self::get_cached_ips_for_display();
        if ( empty( $ips ) ) {
            return '';
        }

        $rules = self::generate_htaccess_rules( $ips );
        $marker = self::HTACCESS_MARKER;

        $output = "# BEGIN {$marker}\n";
        foreach ( $rules as $rule ) {
            $output .= $rule . "\n";
        }
        $output .= "# END {$marker}";

        return $output;
    }

    /**
     * Sync IPs (main function called by cron and manual sync)
     */
    public static function sync_ips() {
        // Check if enabled
        if ( get_option( self::OPTION_PREFIX . 'enabled' ) !== '1' ) {
            self::log( 'Sync skipped - plugin disabled' );
            return false;
        }

        self::log( 'Starting IP sync...' );

        $ips = self::get_all_ips();

        if ( empty( $ips ) ) {
            self::log( 'ERROR: No valid IPs to whitelist' );
            update_option( self::OPTION_PREFIX . 'last_status', 'error' );
            return false;
        }

        // Cache IPs for display (always do this, even on nginx)
        set_transient( self::CACHE_KEY, $ips, self::CACHE_EXPIRY );
        update_option( self::OPTION_PREFIX . 'last_sync', current_time( 'timestamp' ) );
        update_option( self::OPTION_PREFIX . 'last_ip_count', count( $ips ) );

        // On nginx, skip .htaccess update but mark as success (manual config required)
        if ( self::is_nginx() ) {
            self::log( 'nginx detected - skipping .htaccess update. Use nginx config from admin panel.' );
            update_option( self::OPTION_PREFIX . 'last_status', 'nginx' );
            return true;
        }

        $result = self::update_htaccess( $ips );

        return $result;
    }

    /**
     * Handle manual sync from admin
     */
    public static function handle_manual_sync() {
        // Verify nonce and capability
        if ( ! current_user_can( 'manage_options' ) ) {
            wp_die( 'Unauthorized' );
        }

        check_admin_referer( 'xmlrpc_whitelist_sync_action' );

        $result = self::sync_ips();

        // Redirect back with status
        $redirect_url = add_query_arg(
            array(
                'page' => 'whitelist-xml-rpc',
                'synced' => $result ? '1' : '0',
            ),
            admin_url( 'options-general.php' )
        );

        wp_safe_redirect( $redirect_url );
        exit;
    }

    /**
     * Show admin notices
     */
    public static function admin_notices() {
        if ( ! isset( $_GET['page'] ) || $_GET['page'] !== 'whitelist-xml-rpc' ) {
            return;
        }

        if ( isset( $_GET['synced'] ) ) {
            $class = $_GET['synced'] === '1' ? 'notice-success' : 'notice-error';
            $message = $_GET['synced'] === '1'
                ? __( 'IP whitelist synced successfully!', 'whitelist-xml-rpc' )
                : __( 'Failed to sync IP whitelist. Check the log below.', 'whitelist-xml-rpc' );

            printf( '<div class="notice %s is-dismissible"><p>%s</p></div>', esc_attr( $class ), esc_html( $message ) );
        }

        // Re-sync after settings change (WordPress Settings API handles nonce via options.php)
        // Only sync if coming from our settings page with valid referrer
        if ( isset( $_GET['settings-updated'] ) && $_GET['settings-updated'] === 'true' ) {
            $referer = wp_get_referer();
            if ( $referer && strpos( $referer, 'options.php' ) !== false ) {
                self::sync_ips();
            }
        }
    }

    /**
     * Log messages
     */
    public static function log( $message ) {
        $log = get_option( self::OPTION_PREFIX . 'log', array() );

        // Keep only last 50 entries
        if ( count( $log ) >= 50 ) {
            $log = array_slice( $log, -49 );
        }

        $log[] = array(
            'time' => current_time( 'Y-m-d H:i:s' ),
            'message' => $message,
        );

        update_option( self::OPTION_PREFIX . 'log', $log );
    }

    /**
     * Output admin page styles
     */
    public static function admin_styles() {
        ?>
        <style>
            .xmlrpc-wrap {
                max-width: 1200px;
            }
            .xmlrpc-header {
                display: flex;
                align-items: center;
                margin-bottom: 20px;
                padding-bottom: 20px;
                border-bottom: 1px solid #c3c4c7;
            }
            .xmlrpc-header h1 {
                display: flex;
                align-items: center;
                gap: 10px;
                margin: 0;
                padding: 0;
            }
            .xmlrpc-header .dashicons {
                font-size: 32px;
                width: 32px;
                height: 32px;
                color: #2271b1;
            }
            .xmlrpc-status-hero {
                background: linear-gradient(135deg, #1d2327 0%, #2c3338 100%);
                border-radius: 8px;
                padding: 30px;
                margin-bottom: 25px;
                color: #fff;
                display: flex;
                align-items: center;
                gap: 30px;
                box-shadow: 0 2px 8px rgba(0,0,0,0.12);
            }
            .xmlrpc-status-hero.status-active {
                background: linear-gradient(135deg, #00a32a 0%, #007017 100%);
            }
            .xmlrpc-status-hero.status-warning {
                background: linear-gradient(135deg, #dba617 0%, #996800 100%);
            }
            .xmlrpc-status-hero.status-error {
                background: linear-gradient(135deg, #d63638 0%, #a00 100%);
            }
            .xmlrpc-status-hero.status-disabled {
                background: linear-gradient(135deg, #646970 0%, #3c434a 100%);
            }
            .xmlrpc-status-icon {
                font-size: 64px;
                width: 64px;
                height: 64px;
                opacity: 0.9;
            }
            .xmlrpc-status-content h2 {
                margin: 0 0 8px 0;
                font-size: 24px;
                font-weight: 600;
                color: #fff;
            }
            .xmlrpc-status-content p {
                margin: 0;
                opacity: 0.9;
                font-size: 14px;
            }
            .xmlrpc-status-meta {
                margin-left: auto;
                text-align: right;
                font-size: 13px;
                opacity: 0.85;
            }
            .xmlrpc-status-meta strong {
                display: block;
                font-size: 28px;
                font-weight: 600;
                margin-bottom: 4px;
            }
            .xmlrpc-grid {
                display: grid;
                grid-template-columns: 1fr 1fr;
                gap: 20px;
                margin-bottom: 20px;
            }
            @media (max-width: 1200px) {
                .xmlrpc-grid {
                    grid-template-columns: 1fr;
                }
            }
            .xmlrpc-card {
                background: #fff;
                border: 1px solid #c3c4c7;
                border-radius: 4px;
                box-shadow: 0 1px 1px rgba(0,0,0,0.04);
            }
            .xmlrpc-card-header {
                display: flex;
                align-items: center;
                gap: 10px;
                padding: 15px 20px;
                border-bottom: 1px solid #c3c4c7;
                background: #f6f7f7;
            }
            .xmlrpc-card-header h3 {
                margin: 0;
                font-size: 14px;
                font-weight: 600;
            }
            .xmlrpc-card-header .dashicons {
                color: #2271b1;
            }
            .xmlrpc-card-body {
                padding: 20px;
            }
            .xmlrpc-stat-grid {
                display: grid;
                grid-template-columns: repeat(2, 1fr);
                gap: 15px;
            }
            .xmlrpc-stat-item {
                background: #f6f7f7;
                border-radius: 4px;
                padding: 15px;
                text-align: center;
            }
            .xmlrpc-stat-item .dashicons {
                font-size: 24px;
                width: 24px;
                height: 24px;
                color: #2271b1;
                margin-bottom: 8px;
            }
            .xmlrpc-stat-value {
                font-size: 20px;
                font-weight: 600;
                color: #1d2327;
                margin-bottom: 4px;
            }
            .xmlrpc-stat-label {
                font-size: 12px;
                color: #646970;
                text-transform: uppercase;
                letter-spacing: 0.5px;
            }
            .xmlrpc-info-list {
                margin: 0;
                padding: 0;
                list-style: none;
            }
            .xmlrpc-info-list li {
                display: flex;
                justify-content: space-between;
                padding: 12px 0;
                border-bottom: 1px solid #f0f0f1;
            }
            .xmlrpc-info-list li:last-child {
                border-bottom: none;
            }
            .xmlrpc-info-list .label {
                color: #646970;
                font-size: 13px;
            }
            .xmlrpc-info-list .value {
                font-weight: 500;
                color: #1d2327;
                font-size: 13px;
            }
            .xmlrpc-badge {
                display: inline-flex;
                align-items: center;
                gap: 4px;
                padding: 3px 10px;
                border-radius: 12px;
                font-size: 12px;
                font-weight: 500;
            }
            .xmlrpc-badge-success {
                background: #edfaef;
                color: #00a32a;
            }
            .xmlrpc-badge-warning {
                background: #fcf9e8;
                color: #996800;
            }
            .xmlrpc-badge-error {
                background: #fcf0f1;
                color: #d63638;
            }
            .xmlrpc-badge-info {
                background: #f0f6fc;
                color: #2271b1;
            }
            .xmlrpc-actions {
                display: flex;
                gap: 10px;
                margin-top: 15px;
            }
            .xmlrpc-settings-form .form-table th {
                width: 200px;
                padding: 15px 10px 15px 0;
            }
            .xmlrpc-settings-form .form-table td {
                padding: 15px 10px;
            }
            .xmlrpc-code-block {
                background: #1d2327;
                color: #50c878;
                border-radius: 4px;
                padding: 15px;
                font-family: Consolas, Monaco, monospace;
                font-size: 12px;
                line-height: 1.6;
                overflow-x: auto;
                max-height: 250px;
                overflow-y: auto;
            }
            .xmlrpc-code-block::-webkit-scrollbar {
                width: 8px;
                height: 8px;
            }
            .xmlrpc-code-block::-webkit-scrollbar-track {
                background: #2c3338;
            }
            .xmlrpc-code-block::-webkit-scrollbar-thumb {
                background: #50575e;
                border-radius: 4px;
            }
            .xmlrpc-ip-grid {
                display: grid;
                grid-template-columns: repeat(auto-fill, minmax(140px, 1fr));
                gap: 8px;
                max-height: 200px;
                overflow-y: auto;
                padding: 5px;
            }
            .xmlrpc-ip-item {
                background: #f0f0f1;
                padding: 6px 10px;
                border-radius: 4px;
                font-family: Consolas, Monaco, monospace;
                font-size: 12px;
                color: #1d2327;
            }
            .xmlrpc-log-entry {
                padding: 8px 12px;
                margin-bottom: 4px;
                border-radius: 4px;
                font-size: 12px;
                font-family: Consolas, Monaco, monospace;
            }
            .xmlrpc-log-entry:nth-child(odd) {
                background: #f6f7f7;
            }
            .xmlrpc-log-time {
                color: #646970;
                margin-right: 10px;
            }
            .xmlrpc-log-message {
                color: #1d2327;
            }
            .xmlrpc-log-message.error {
                color: #d63638;
            }
            .xmlrpc-log-message.success {
                color: #00a32a;
            }
            .xmlrpc-instructions {
                background: #f6f7f7;
                border-left: 4px solid #2271b1;
                padding: 15px 20px;
                margin-top: 15px;
                border-radius: 0 4px 4px 0;
            }
            .xmlrpc-instructions h4 {
                margin: 0 0 10px 0;
                font-size: 13px;
            }
            .xmlrpc-instructions ol {
                margin: 0;
                padding-left: 20px;
            }
            .xmlrpc-instructions li {
                margin-bottom: 5px;
                font-size: 13px;
                color: #646970;
            }
            .xmlrpc-full-width {
                grid-column: 1 / -1;
            }
            .xmlrpc-copy-btn {
                position: absolute;
                top: 10px;
                right: 10px;
                background: rgba(255,255,255,0.1);
                border: 1px solid rgba(255,255,255,0.2);
                color: #fff;
                padding: 5px 12px;
                border-radius: 4px;
                cursor: pointer;
                font-size: 12px;
                transition: all 0.2s;
            }
            .xmlrpc-copy-btn:hover {
                background: rgba(255,255,255,0.2);
            }
            .xmlrpc-code-wrapper {
                position: relative;
            }
        </style>
        <?php
    }

    /**
     * Render settings page
     */
    public static function render_settings_page() {
        $enabled = get_option( self::OPTION_PREFIX . 'enabled', '1' );
        $ip_source = get_option( self::OPTION_PREFIX . 'ip_source', self::DEFAULT_IP_SOURCE );
        $custom_ips = get_option( self::OPTION_PREFIX . 'custom_ips', '' );
        $last_sync = get_option( self::OPTION_PREFIX . 'last_sync', 0 );
        $last_ip_count = get_option( self::OPTION_PREFIX . 'last_ip_count', 0 );
        $last_status = get_option( self::OPTION_PREFIX . 'last_status', 'unknown' );
        $log = get_option( self::OPTION_PREFIX . 'log', array() );
        $next_scheduled = wp_next_scheduled( self::CRON_HOOK );

        // Get cached IPs for display (avoids 30s remote fetch on page load)
        $current_ips = self::get_cached_ips_for_display();
        $cache_status = get_transient( self::CACHE_KEY ) !== false ? 'cached' : 'not_cached';

        // Detect server type
        $is_nginx = self::is_nginx();

        // Verify .htaccess rules exist (only on admin page load, Apache only)
        $htaccess_verified = $is_nginx ? false : self::verify_htaccess_rules();

        // Determine status
        $status_class = 'status-disabled';
        $status_icon = 'dashicons-shield-alt';
        $status_title = __( 'Protection Disabled', 'whitelist-xml-rpc' );
        $status_desc = __( 'XML-RPC protection is currently disabled.', 'whitelist-xml-rpc' );

        if ( $enabled === '1' ) {
            if ( $is_nginx ) {
                $status_class = 'status-warning';
                $status_icon = 'dashicons-warning';
                $status_title = __( 'Manual Configuration Required', 'whitelist-xml-rpc' );
                $status_desc = __( 'nginx detected. Copy the configuration below to your server.', 'whitelist-xml-rpc' );
            } elseif ( $htaccess_verified ) {
                $status_class = 'status-active';
                $status_icon = 'dashicons-shield';
                $status_title = __( 'Protection Active', 'whitelist-xml-rpc' );
                $status_desc = __( 'Your XML-RPC endpoint is protected. Only whitelisted IPs can access it.', 'whitelist-xml-rpc' );
            } else {
                $status_class = 'status-error';
                $status_icon = 'dashicons-dismiss';
                $status_title = __( 'Protection Not Active', 'whitelist-xml-rpc' );
                $status_desc = __( '.htaccess rules are missing. Click "Sync Now" to activate protection.', 'whitelist-xml-rpc' );
            }
        }

        // Output styles
        self::admin_styles();

        ?>
        <div class="wrap xmlrpc-wrap">
            <div class="xmlrpc-header">
                <h1>
                    <span class="dashicons dashicons-shield"></span>
                    <?php echo esc_html( get_admin_page_title() ); ?>
                </h1>
            </div>

            <!-- Status Hero -->
            <div class="xmlrpc-status-hero <?php echo esc_attr( $status_class ); ?>">
                <span class="dashicons <?php echo esc_attr( $status_icon ); ?> xmlrpc-status-icon"></span>
                <div class="xmlrpc-status-content">
                    <h2><?php echo esc_html( $status_title ); ?></h2>
                    <p><?php echo esc_html( $status_desc ); ?></p>
                </div>
                <div class="xmlrpc-status-meta">
                    <strong><?php echo esc_html( $last_ip_count ); ?></strong>
                    <?php _e( 'Whitelisted IPs', 'whitelist-xml-rpc' ); ?>
                </div>
            </div>

            <!-- Main Grid -->
            <div class="xmlrpc-grid">
                <!-- Quick Stats -->
                <div class="xmlrpc-card">
                    <div class="xmlrpc-card-header">
                        <span class="dashicons dashicons-chart-bar"></span>
                        <h3><?php _e( 'Quick Stats', 'whitelist-xml-rpc' ); ?></h3>
                    </div>
                    <div class="xmlrpc-card-body">
                        <div class="xmlrpc-stat-grid">
                            <div class="xmlrpc-stat-item">
                                <span class="dashicons dashicons-admin-network"></span>
                                <div class="xmlrpc-stat-value"><?php echo esc_html( $last_ip_count ); ?></div>
                                <div class="xmlrpc-stat-label"><?php _e( 'IPs Whitelisted', 'whitelist-xml-rpc' ); ?></div>
                            </div>
                            <div class="xmlrpc-stat-item">
                                <span class="dashicons dashicons-update"></span>
                                <div class="xmlrpc-stat-value">
                                    <?php echo $last_sync ? esc_html( human_time_diff( $last_sync, current_time( 'timestamp' ) ) ) : '—'; ?>
                                </div>
                                <div class="xmlrpc-stat-label"><?php _e( 'Since Last Sync', 'whitelist-xml-rpc' ); ?></div>
                            </div>
                            <div class="xmlrpc-stat-item">
                                <span class="dashicons dashicons-cloud"></span>
                                <div class="xmlrpc-stat-value"><?php echo $is_nginx ? 'nginx' : 'Apache'; ?></div>
                                <div class="xmlrpc-stat-label"><?php _e( 'Server Type', 'whitelist-xml-rpc' ); ?></div>
                            </div>
                            <div class="xmlrpc-stat-item">
                                <span class="dashicons dashicons-calendar-alt"></span>
                                <div class="xmlrpc-stat-value"><?php _e( 'Daily', 'whitelist-xml-rpc' ); ?></div>
                                <div class="xmlrpc-stat-label"><?php _e( 'Sync Schedule', 'whitelist-xml-rpc' ); ?></div>
                            </div>
                        </div>
                        <div class="xmlrpc-actions">
                            <form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>" style="margin: 0;">
                                <input type="hidden" name="action" value="xmlrpc_whitelist_sync">
                                <?php wp_nonce_field( 'xmlrpc_whitelist_sync_action' ); ?>
                                <button type="submit" class="button button-primary">
                                    <span class="dashicons dashicons-update" style="vertical-align: middle; margin-right: 5px;"></span>
                                    <?php _e( 'Sync Now', 'whitelist-xml-rpc' ); ?>
                                </button>
                            </form>
                        </div>
                    </div>
                </div>

                <!-- System Info -->
                <div class="xmlrpc-card">
                    <div class="xmlrpc-card-header">
                        <span class="dashicons dashicons-info-outline"></span>
                        <h3><?php _e( 'System Information', 'whitelist-xml-rpc' ); ?></h3>
                    </div>
                    <div class="xmlrpc-card-body">
                        <ul class="xmlrpc-info-list">
                            <li>
                                <span class="label"><?php _e( 'Protection', 'whitelist-xml-rpc' ); ?></span>
                                <span class="value">
                                    <?php if ( $enabled === '1' ) : ?>
                                        <span class="xmlrpc-badge xmlrpc-badge-success"><?php _e( 'Enabled', 'whitelist-xml-rpc' ); ?></span>
                                    <?php else : ?>
                                        <span class="xmlrpc-badge xmlrpc-badge-error"><?php _e( 'Disabled', 'whitelist-xml-rpc' ); ?></span>
                                    <?php endif; ?>
                                </span>
                            </li>
                            <li>
                                <span class="label"><?php _e( 'Server Type', 'whitelist-xml-rpc' ); ?></span>
                                <span class="value">
                                    <span class="xmlrpc-badge xmlrpc-badge-info"><?php echo $is_nginx ? 'nginx' : 'Apache'; ?></span>
                                </span>
                            </li>
                            <?php if ( ! $is_nginx ) : ?>
                            <li>
                                <span class="label"><?php _e( '.htaccess', 'whitelist-xml-rpc' ); ?></span>
                                <span class="value">
                                    <?php if ( self::is_htaccess_writable() ) : ?>
                                        <span class="xmlrpc-badge xmlrpc-badge-success"><?php _e( 'Writable', 'whitelist-xml-rpc' ); ?></span>
                                    <?php else : ?>
                                        <span class="xmlrpc-badge xmlrpc-badge-warning"><?php _e( 'Not Writable', 'whitelist-xml-rpc' ); ?></span>
                                    <?php endif; ?>
                                </span>
                            </li>
                            <?php endif; ?>
                            <li>
                                <span class="label"><?php _e( 'Last Sync', 'whitelist-xml-rpc' ); ?></span>
                                <span class="value">
                                    <?php
                                    if ( $last_sync ) {
                                        echo esc_html( date_i18n( 'M j, Y @ H:i', $last_sync ) );
                                    } else {
                                        _e( 'Never', 'whitelist-xml-rpc' );
                                    }
                                    ?>
                                </span>
                            </li>
                            <li>
                                <span class="label"><?php _e( 'Next Sync', 'whitelist-xml-rpc' ); ?></span>
                                <span class="value">
                                    <?php
                                    if ( $next_scheduled ) {
                                        echo esc_html( date_i18n( 'M j, Y @ H:i', $next_scheduled ) );
                                    } else {
                                        _e( 'Not scheduled', 'whitelist-xml-rpc' );
                                    }
                                    ?>
                                </span>
                            </li>
                        </ul>
                    </div>
                </div>

                <!-- Settings -->
                <div class="xmlrpc-card xmlrpc-full-width">
                    <div class="xmlrpc-card-header">
                        <span class="dashicons dashicons-admin-settings"></span>
                        <h3><?php _e( 'Settings', 'whitelist-xml-rpc' ); ?></h3>
                    </div>
                    <div class="xmlrpc-card-body">
                        <form method="post" action="options.php" class="xmlrpc-settings-form">
                            <?php settings_fields( 'xmlrpc_whitelist_settings' ); ?>
                            <table class="form-table">
                                <tr>
                                    <th scope="row"><?php _e( 'Enable Protection', 'whitelist-xml-rpc' ); ?></th>
                                    <td>
                                        <label class="xmlrpc-toggle">
                                            <input type="checkbox" name="<?php echo self::OPTION_PREFIX; ?>enabled" value="1" <?php checked( $enabled, '1' ); ?>>
                                            <?php _e( 'Block xmlrpc.php access except for whitelisted IPs', 'whitelist-xml-rpc' ); ?>
                                        </label>
                                        <p class="description"><?php _e( 'When disabled, .htaccess rules will be removed and all IPs can access xmlrpc.php.', 'whitelist-xml-rpc' ); ?></p>
                                    </td>
                                </tr>
                                <tr>
                                    <th scope="row"><?php _e( 'IP Source URL', 'whitelist-xml-rpc' ); ?></th>
                                    <td>
                                        <input type="url" name="<?php echo self::OPTION_PREFIX; ?>ip_source" value="<?php echo esc_attr( $ip_source ); ?>" class="regular-text code">
                                        <p class="description"><?php _e( 'URL to fetch Jetpack server IPs from (one IP/CIDR per line)', 'whitelist-xml-rpc' ); ?></p>
                                    </td>
                                </tr>
                                <tr>
                                    <th scope="row"><?php _e( 'Custom IPs', 'whitelist-xml-rpc' ); ?></th>
                                    <td>
                                        <textarea name="<?php echo self::OPTION_PREFIX; ?>custom_ips" rows="4" class="large-text code" placeholder="192.168.1.1&#10;10.0.0.0/8"><?php echo esc_textarea( $custom_ips ); ?></textarea>
                                        <p class="description"><?php _e( 'Additional IPs to whitelist (one per line). Supports CIDR notation like 192.168.1.0/24', 'whitelist-xml-rpc' ); ?></p>
                                    </td>
                                </tr>
                            </table>
                            <?php submit_button( __( 'Save Settings', 'whitelist-xml-rpc' ), 'primary' ); ?>
                        </form>
                    </div>
                </div>

                <!-- Whitelisted IPs -->
                <div class="xmlrpc-card">
                    <div class="xmlrpc-card-header">
                        <span class="dashicons dashicons-networking"></span>
                        <h3>
                            <?php _e( 'Whitelisted IPs', 'whitelist-xml-rpc' ); ?>
                            <?php if ( $cache_status === 'not_cached' ) : ?>
                                <small style="font-weight: normal; color: #646970; margin-left: 10px;">(<?php _e( 'sync to refresh', 'whitelist-xml-rpc' ); ?>)</small>
                            <?php endif; ?>
                        </h3>
                    </div>
                    <div class="xmlrpc-card-body">
                        <?php if ( ! empty( $current_ips ) ) : ?>
                            <div class="xmlrpc-ip-grid">
                                <?php foreach ( array_slice( $current_ips, 0, 50 ) as $ip ) : ?>
                                    <div class="xmlrpc-ip-item"><?php echo esc_html( $ip ); ?></div>
                                <?php endforeach; ?>
                                <?php if ( count( $current_ips ) > 50 ) : ?>
                                    <div class="xmlrpc-ip-item" style="background: #2271b1; color: #fff;">+<?php echo count( $current_ips ) - 50; ?> more</div>
                                <?php endif; ?>
                            </div>
                        <?php else : ?>
                            <p style="color: #646970; margin: 0;"><?php _e( 'No IPs loaded. Click "Sync Now" to fetch the whitelist.', 'whitelist-xml-rpc' ); ?></p>
                        <?php endif; ?>
                    </div>
                </div>

                <!-- Activity Log -->
                <div class="xmlrpc-card">
                    <div class="xmlrpc-card-header">
                        <span class="dashicons dashicons-list-view"></span>
                        <h3><?php _e( 'Activity Log', 'whitelist-xml-rpc' ); ?></h3>
                    </div>
                    <div class="xmlrpc-card-body" style="max-height: 300px; overflow-y: auto;">
                        <?php if ( ! empty( $log ) ) : ?>
                            <?php
                            $log_reversed = array_reverse( array_slice( $log, -20 ) );
                            foreach ( $log_reversed as $entry ) :
                                $msg_class = '';
                                if ( strpos( $entry['message'], 'ERROR' ) !== false ) {
                                    $msg_class = 'error';
                                } elseif ( strpos( $entry['message'], 'Successfully' ) !== false ) {
                                    $msg_class = 'success';
                                }
                            ?>
                                <div class="xmlrpc-log-entry">
                                    <span class="xmlrpc-log-time"><?php echo esc_html( $entry['time'] ); ?></span>
                                    <span class="xmlrpc-log-message <?php echo esc_attr( $msg_class ); ?>"><?php echo esc_html( $entry['message'] ); ?></span>
                                </div>
                            <?php endforeach; ?>
                        <?php else : ?>
                            <p style="color: #646970; margin: 0;"><?php _e( 'No log entries yet.', 'whitelist-xml-rpc' ); ?></p>
                        <?php endif; ?>
                    </div>
                </div>

                <!-- Server Configuration -->
                <?php if ( $is_nginx ) : ?>
                    <?php $nginx_rules = self::generate_nginx_rules( $current_ips ); ?>
                    <?php if ( ! empty( $nginx_rules ) ) : ?>
                    <div class="xmlrpc-card xmlrpc-full-width">
                        <div class="xmlrpc-card-header" style="background: #fcf9e8; border-color: #dba617;">
                            <span class="dashicons dashicons-warning" style="color: #996800;"></span>
                            <h3 style="color: #996800;"><?php _e( 'nginx Configuration Required', 'whitelist-xml-rpc' ); ?></h3>
                        </div>
                        <div class="xmlrpc-card-body">
                            <p><?php _e( 'Since you\'re running nginx, add these rules to your server configuration:', 'whitelist-xml-rpc' ); ?></p>
                            <div class="xmlrpc-code-wrapper">
                                <button type="button" class="xmlrpc-copy-btn" onclick="navigator.clipboard.writeText(this.nextElementSibling.textContent).then(() => { this.textContent = 'Copied!'; setTimeout(() => this.textContent = 'Copy', 2000); });">Copy</button>
                                <pre class="xmlrpc-code-block"><?php echo esc_html( $nginx_rules ); ?></pre>
                            </div>
                            <div class="xmlrpc-instructions">
                                <h4><?php _e( 'Instructions:', 'whitelist-xml-rpc' ); ?></h4>
                                <ol>
                                    <li><?php _e( 'SSH into your server', 'whitelist-xml-rpc' ); ?></li>
                                    <li><?php _e( 'Open your nginx site configuration', 'whitelist-xml-rpc' ); ?></li>
                                    <li><?php _e( 'Add this location block inside your server {} block', 'whitelist-xml-rpc' ); ?></li>
                                    <li><?php _e( 'Adjust the fastcgi_pass path to match your PHP-FPM socket', 'whitelist-xml-rpc' ); ?></li>
                                    <li><?php _e( 'Test: nginx -t', 'whitelist-xml-rpc' ); ?></li>
                                    <li><?php _e( 'Reload: systemctl reload nginx', 'whitelist-xml-rpc' ); ?></li>
                                </ol>
                            </div>
                        </div>
                    </div>
                    <?php endif; ?>
                <?php else : ?>
                    <?php $manual_rules = self::get_manual_htaccess_rules(); ?>
                    <?php if ( ! empty( $manual_rules ) && ! self::is_htaccess_writable() ) : ?>
                    <div class="xmlrpc-card xmlrpc-full-width">
                        <div class="xmlrpc-card-header" style="background: #fcf9e8; border-color: #dba617;">
                            <span class="dashicons dashicons-warning" style="color: #996800;"></span>
                            <h3 style="color: #996800;"><?php _e( 'Manual .htaccess Configuration Required', 'whitelist-xml-rpc' ); ?></h3>
                        </div>
                        <div class="xmlrpc-card-body">
                            <p><?php _e( 'Your .htaccess file is not writable. Add these rules manually:', 'whitelist-xml-rpc' ); ?></p>
                            <div class="xmlrpc-code-wrapper">
                                <button type="button" class="xmlrpc-copy-btn" onclick="navigator.clipboard.writeText(this.nextElementSibling.textContent).then(() => { this.textContent = 'Copied!'; setTimeout(() => this.textContent = 'Copy', 2000); });">Copy</button>
                                <pre class="xmlrpc-code-block"><?php echo esc_html( $manual_rules ); ?></pre>
                            </div>
                            <div class="xmlrpc-instructions">
                                <h4><?php _e( 'Instructions:', 'whitelist-xml-rpc' ); ?></h4>
                                <ol>
                                    <li><?php _e( 'Connect via FTP/SFTP or file manager', 'whitelist-xml-rpc' ); ?></li>
                                    <li><?php _e( 'Open .htaccess in your WordPress root', 'whitelist-xml-rpc' ); ?></li>
                                    <li><?php _e( 'Paste these rules at the top (before # BEGIN WordPress)', 'whitelist-xml-rpc' ); ?></li>
                                    <li><?php _e( 'Save the file', 'whitelist-xml-rpc' ); ?></li>
                                </ol>
                            </div>
                        </div>
                    </div>
                    <?php endif; ?>
                <?php endif; ?>

            </div>
        </div>
        <?php
    }
}

// Initialize the plugin
XMLRPC_IP_Whitelist::init();
