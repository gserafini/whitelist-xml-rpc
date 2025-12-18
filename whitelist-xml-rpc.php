<?php
/**
 * Plugin Name: Whitelist XML-RPC
 * Plugin URI: https://github.com/gserafini/whitelist-xml-rpc
 * Description: Automatically whitelists Jetpack server IPs for XML-RPC access, blocking all other xmlrpc.php requests with 403 Forbidden. Syncs daily via WordPress cron.
 * Version: 1.0.0
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

    const VERSION = '1.0.1';
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

        $result = self::update_htaccess( $ips );

        // Cache IPs for display (avoids remote fetch on settings page)
        if ( $result ) {
            set_transient( self::CACHE_KEY, $ips, self::CACHE_EXPIRY );
        }

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

        // Verify .htaccess rules exist (only on admin page load)
        $htaccess_verified = self::verify_htaccess_rules();

        ?>
        <div class="wrap">
            <h1><?php echo esc_html( get_admin_page_title() ); ?></h1>

            <div class="card" style="max-width: 800px; margin-bottom: 20px;">
                <h2 style="margin-top: 0;"><?php _e( 'Status', 'whitelist-xml-rpc' ); ?></h2>
                <table class="form-table">
                    <tr>
                        <th><?php _e( 'Protection Status', 'whitelist-xml-rpc' ); ?></th>
                        <td>
                            <?php if ( $enabled !== '1' ) : ?>
                                <span style="color: gray;">&#10007; <?php _e( 'Disabled', 'whitelist-xml-rpc' ); ?></span>
                            <?php elseif ( $htaccess_verified ) : ?>
                                <span style="color: green; font-weight: bold;">&#10003; <?php _e( 'Active', 'whitelist-xml-rpc' ); ?></span>
                            <?php else : ?>
                                <span style="color: red; font-weight: bold;">&#10007; <?php _e( 'Not Active - .htaccess rules missing! Click Sync Now', 'whitelist-xml-rpc' ); ?></span>
                            <?php endif; ?>
                        </td>
                    </tr>
                    <tr>
                        <th><?php _e( 'Last Sync', 'whitelist-xml-rpc' ); ?></th>
                        <td>
                            <?php
                            if ( $last_sync ) {
                                echo esc_html( date_i18n( get_option( 'date_format' ) . ' ' . get_option( 'time_format' ), $last_sync ) );
                                echo ' (' . esc_html( human_time_diff( $last_sync, current_time( 'timestamp' ) ) ) . ' ago)';
                            } else {
                                _e( 'Never', 'whitelist-xml-rpc' );
                            }
                            ?>
                        </td>
                    </tr>
                    <tr>
                        <th><?php _e( 'Whitelisted IPs', 'whitelist-xml-rpc' ); ?></th>
                        <td><?php echo esc_html( $last_ip_count ); ?></td>
                    </tr>
                    <tr>
                        <th><?php _e( 'Next Scheduled Sync', 'whitelist-xml-rpc' ); ?></th>
                        <td>
                            <?php
                            if ( $next_scheduled ) {
                                echo esc_html( date_i18n( get_option( 'date_format' ) . ' ' . get_option( 'time_format' ), $next_scheduled ) );
                            } else {
                                _e( 'Not scheduled', 'whitelist-xml-rpc' );
                            }
                            ?>
                        </td>
                    </tr>
                    <tr>
                        <th><?php _e( '.htaccess Status', 'whitelist-xml-rpc' ); ?></th>
                        <td>
                            <?php if ( self::is_htaccess_writable() ) : ?>
                                <span style="color: green;">&#10003; <?php _e( 'Writable', 'whitelist-xml-rpc' ); ?></span>
                            <?php else : ?>
                                <span style="color: orange;">&#9888; <?php _e( 'Not writable - see Manual Rules below', 'whitelist-xml-rpc' ); ?></span>
                            <?php endif; ?>
                        </td>
                    </tr>
                </table>

                <form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>" style="margin-top: 10px;">
                    <input type="hidden" name="action" value="xmlrpc_whitelist_sync">
                    <?php wp_nonce_field( 'xmlrpc_whitelist_sync_action' ); ?>
                    <?php submit_button( __( 'Sync Now', 'whitelist-xml-rpc' ), 'secondary', 'submit', false ); ?>
                </form>
            </div>

            <form method="post" action="options.php">
                <?php settings_fields( 'xmlrpc_whitelist_settings' ); ?>

                <table class="form-table">
                    <tr>
                        <th scope="row"><?php _e( 'Enable Protection', 'whitelist-xml-rpc' ); ?></th>
                        <td>
                            <label>
                                <input type="checkbox" name="<?php echo self::OPTION_PREFIX; ?>enabled" value="1" <?php checked( $enabled, '1' ); ?>>
                                <?php _e( 'Block xmlrpc.php access except for whitelisted IPs', 'whitelist-xml-rpc' ); ?>
                            </label>
                            <p class="description"><?php _e( 'When disabled, .htaccess rules will be removed.', 'whitelist-xml-rpc' ); ?></p>
                        </td>
                    </tr>
                    <tr>
                        <th scope="row"><?php _e( 'IP Source URL', 'whitelist-xml-rpc' ); ?></th>
                        <td>
                            <input type="url" name="<?php echo self::OPTION_PREFIX; ?>ip_source" value="<?php echo esc_attr( $ip_source ); ?>" class="regular-text">
                            <p class="description"><?php _e( 'URL to fetch IP list from (one IP/CIDR per line)', 'whitelist-xml-rpc' ); ?></p>
                        </td>
                    </tr>
                    <tr>
                        <th scope="row"><?php _e( 'Additional Custom IPs', 'whitelist-xml-rpc' ); ?></th>
                        <td>
                            <textarea name="<?php echo self::OPTION_PREFIX; ?>custom_ips" rows="5" class="large-text code"><?php echo esc_textarea( $custom_ips ); ?></textarea>
                            <p class="description"><?php _e( 'Additional IPs to whitelist (one per line, supports CIDR notation)', 'whitelist-xml-rpc' ); ?></p>
                        </td>
                    </tr>
                </table>

                <?php submit_button(); ?>
            </form>

            <div class="card" style="max-width: 800px; margin-top: 20px;">
                <h2 style="margin-top: 0;">
                    <?php _e( 'Current Whitelisted IPs', 'whitelist-xml-rpc' ); ?>
                    <?php if ( $cache_status === 'not_cached' ) : ?>
                        <small style="font-weight: normal; color: #666;">(<?php _e( 'click Sync Now to refresh', 'whitelist-xml-rpc' ); ?>)</small>
                    <?php endif; ?>
                </h2>
                <pre style="background: #f0f0f0; padding: 10px; max-height: 200px; overflow-y: auto;"><?php
                    if ( ! empty( $current_ips ) ) {
                        echo esc_html( implode( "\n", $current_ips ) );
                    } else {
                        _e( 'No IPs loaded - click Sync Now to fetch', 'whitelist-xml-rpc' );
                    }
                ?></pre>
            </div>

            <div class="card" style="max-width: 800px; margin-top: 20px;">
                <h2 style="margin-top: 0;"><?php _e( 'Activity Log', 'whitelist-xml-rpc' ); ?></h2>
                <pre style="background: #f0f0f0; padding: 10px; max-height: 300px; overflow-y: auto; font-size: 12px;"><?php
                    if ( ! empty( $log ) ) {
                        $log_reversed = array_reverse( $log );
                        foreach ( $log_reversed as $entry ) {
                            echo esc_html( '[' . $entry['time'] . '] ' . $entry['message'] ) . "\n";
                        }
                    } else {
                        _e( 'No log entries', 'whitelist-xml-rpc' );
                    }
                ?></pre>
            </div>

            <?php
            $manual_rules = self::get_manual_htaccess_rules();
            if ( ! empty( $manual_rules ) ) :
            ?>
            <div class="card" style="max-width: 800px; margin-top: 20px; <?php echo self::is_htaccess_writable() ? '' : 'border-left: 4px solid #ffb900;'; ?>">
                <h2 style="margin-top: 0;">
                    <?php _e( 'Manual .htaccess Rules', 'whitelist-xml-rpc' ); ?>
                    <?php if ( ! self::is_htaccess_writable() ) : ?>
                        <span style="color: #d63638; font-size: 14px; font-weight: normal;"><?php _e( '(Required - .htaccess not writable)', 'whitelist-xml-rpc' ); ?></span>
                    <?php endif; ?>
                </h2>
                <p class="description">
                    <?php _e( 'If your .htaccess file is not writable by WordPress, copy and paste these rules into your .htaccess file manually:', 'whitelist-xml-rpc' ); ?>
                </p>
                <textarea readonly style="width: 100%; height: 200px; font-family: monospace; font-size: 12px; background: #f0f0f0;" onclick="this.select();"><?php echo esc_textarea( $manual_rules ); ?></textarea>
                <p class="description" style="margin-top: 10px;">
                    <strong><?php _e( 'Instructions:', 'whitelist-xml-rpc' ); ?></strong><br>
                    1. <?php _e( 'Connect to your server via FTP/SFTP or file manager', 'whitelist-xml-rpc' ); ?><br>
                    2. <?php _e( 'Open the .htaccess file in your WordPress root directory', 'whitelist-xml-rpc' ); ?><br>
                    3. <?php _e( 'Paste these rules at the top of the file (before # BEGIN WordPress)', 'whitelist-xml-rpc' ); ?><br>
                    4. <?php _e( 'Save the file', 'whitelist-xml-rpc' ); ?>
                </p>
            </div>
            <?php endif; ?>

        </div>
        <?php
    }
}

// Initialize the plugin
XMLRPC_IP_Whitelist::init();
