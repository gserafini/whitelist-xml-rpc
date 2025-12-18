<?php
/**
 * PHPUnit Bootstrap for Whitelist XML-RPC Tests
 *
 * For standalone tests without WordPress, we mock the required functions.
 * For integration tests, set WP_TESTS_DIR environment variable.
 */

// Check if we're running WordPress integration tests
$wp_tests_dir = getenv( 'WP_TESTS_DIR' );

if ( $wp_tests_dir ) {
    // Integration tests with WordPress
    require_once $wp_tests_dir . '/includes/functions.php';

    // Load plugin
    tests_add_filter( 'muplugins_loaded', function() {
        require dirname( __DIR__ ) . '/whitelist-xml-rpc.php';
    } );

    require $wp_tests_dir . '/includes/bootstrap.php';
} else {
    // Standalone unit tests - mock WordPress functions
    if ( ! defined( 'ABSPATH' ) ) {
        define( 'ABSPATH', '/tmp/' );
    }

    // Mock WordPress functions needed for tests
    if ( ! function_exists( 'get_option' ) ) {
        function get_option( $option, $default = false ) {
            return $default;
        }
    }

    if ( ! function_exists( 'update_option' ) ) {
        function update_option( $option, $value ) {
            return true;
        }
    }

    if ( ! function_exists( 'get_transient' ) ) {
        function get_transient( $key ) {
            return false;
        }
    }

    if ( ! function_exists( 'set_transient' ) ) {
        function set_transient( $key, $value, $expiry ) {
            return true;
        }
    }

    if ( ! function_exists( 'current_time' ) ) {
        function current_time( $format ) {
            return date( $format );
        }
    }

    // Hook registration mocks
    if ( ! function_exists( 'add_action' ) ) {
        function add_action( $hook, $callback, $priority = 10, $args = 1 ) {
            return true;
        }
    }

    if ( ! function_exists( 'add_filter' ) ) {
        function add_filter( $hook, $callback, $priority = 10, $args = 1 ) {
            return true;
        }
    }

    if ( ! function_exists( 'register_activation_hook' ) ) {
        function register_activation_hook( $file, $callback ) {
            return true;
        }
    }

    if ( ! function_exists( 'register_deactivation_hook' ) ) {
        function register_deactivation_hook( $file, $callback ) {
            return true;
        }
    }

    // Translation mocks
    if ( ! function_exists( '__' ) ) {
        function __( $text, $domain = 'default' ) {
            return $text;
        }
    }

    if ( ! function_exists( '_e' ) ) {
        function _e( $text, $domain = 'default' ) {
            echo $text;
        }
    }

    if ( ! function_exists( 'esc_html__' ) ) {
        function esc_html__( $text, $domain = 'default' ) {
            return htmlspecialchars( $text, ENT_QUOTES, 'UTF-8' );
        }
    }

    if ( ! function_exists( 'esc_attr' ) ) {
        function esc_attr( $text ) {
            return htmlspecialchars( $text, ENT_QUOTES, 'UTF-8' );
        }
    }

    if ( ! function_exists( 'esc_html' ) ) {
        function esc_html( $text ) {
            return htmlspecialchars( $text, ENT_QUOTES, 'UTF-8' );
        }
    }

    // Define HOUR_IN_SECONDS if not defined
    if ( ! defined( 'HOUR_IN_SECONDS' ) ) {
        define( 'HOUR_IN_SECONDS', 3600 );
    }

    // Load the plugin class
    require dirname( __DIR__ ) . '/whitelist-xml-rpc.php';
}
