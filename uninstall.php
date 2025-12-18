<?php
/**
 * Uninstall script for Whitelist XML-RPC
 *
 * This file runs when the plugin is deleted (not just deactivated).
 * It cleans up all plugin data from the database.
 */

// Exit if not called by WordPress
if ( ! defined( 'WP_UNINSTALL_PLUGIN' ) ) {
    exit;
}

// Remove all plugin options
$options = array(
    'xmlrpc_whitelist_enabled',
    'xmlrpc_whitelist_ip_source',
    'xmlrpc_whitelist_custom_ips',
    'xmlrpc_whitelist_last_sync',
    'xmlrpc_whitelist_last_ip_count',
    'xmlrpc_whitelist_last_status',
    'xmlrpc_whitelist_log',
);

foreach ( $options as $option ) {
    delete_option( $option );
}

// Delete transients
delete_transient( 'xmlrpc_whitelist_cached_ips' );

// Clear any scheduled cron events
$timestamp = wp_next_scheduled( 'xmlrpc_whitelist_sync' );
if ( $timestamp ) {
    wp_unschedule_event( $timestamp, 'xmlrpc_whitelist_sync' );
}

// Remove .htaccess rules
if ( ! function_exists( 'insert_with_markers' ) ) {
    require_once ABSPATH . 'wp-admin/includes/misc.php';
}

if ( ! function_exists( 'get_home_path' ) ) {
    require_once ABSPATH . 'wp-admin/includes/file.php';
}

$htaccess_file = get_home_path() . '.htaccess';
if ( file_exists( $htaccess_file ) && is_writable( $htaccess_file ) ) {
    insert_with_markers( $htaccess_file, 'Whitelist XML-RPC', array() );
}
