<?php
/**
 * Tests for XMLRPC_IP_Whitelist::validate_ip()
 *
 * Run with: phpunit --bootstrap tests/bootstrap.php tests/test-validate-ip.php
 */

use PHPUnit\Framework\TestCase;

class ValidateIPTest extends TestCase {

    /**
     * Test valid IPv4 addresses
     */
    public function test_valid_ipv4_addresses() {
        $valid_ips = array(
            '192.168.1.1',
            '10.0.0.1',
            '172.16.0.1',
            '8.8.8.8',
            '1.1.1.1',
            '255.255.255.255',
            '0.0.0.0',
        );

        foreach ( $valid_ips as $ip ) {
            $this->assertTrue(
                XMLRPC_IP_Whitelist::validate_ip( $ip ),
                "Expected $ip to be valid"
            );
        }
    }

    /**
     * Test valid IPv4 with CIDR notation
     */
    public function test_valid_cidr_notation() {
        $valid_cidrs = array(
            '192.168.0.0/24',
            '10.0.0.0/8',
            '172.16.0.0/12',
            '192.0.80.0/20',
            '1.1.1.1/32',
            '0.0.0.0/0',
            '192.168.1.1/16',
        );

        foreach ( $valid_cidrs as $cidr ) {
            $this->assertTrue(
                XMLRPC_IP_Whitelist::validate_ip( $cidr ),
                "Expected $cidr to be valid"
            );
        }
    }

    /**
     * Test invalid IP formats
     */
    public function test_invalid_ip_formats() {
        $invalid_ips = array(
            '',                      // Empty
            'not-an-ip',             // Random string
            '192.168.1',             // Missing octet
            '192.168.1.1.1',         // Extra octet
            '192.168.1.256',         // Octet > 255
            '256.1.1.1',             // First octet > 255
            '999.999.999.999',       // All octets invalid
            '-1.0.0.0',              // Negative
            '192.168.1.1a',          // Letters in IP
            '192.168.1.a',           // Letter as octet
            'abc.def.ghi.jkl',       // All letters
            '::1',                   // IPv6
            '2001:db8::1',           // IPv6
        );

        foreach ( $invalid_ips as $ip ) {
            $this->assertFalse(
                XMLRPC_IP_Whitelist::validate_ip( $ip ),
                "Expected '$ip' to be invalid"
            );
        }
    }

    /**
     * Test invalid CIDR notation
     */
    public function test_invalid_cidr_notation() {
        $invalid_cidrs = array(
            '192.168.1.1/33',        // CIDR > 32
            '192.168.1.1/64',        // CIDR way too large
            '192.168.1.1/-1',        // Negative CIDR
            '192.168.1.1/abc',       // Non-numeric CIDR
            '192.168.1.1/',          // Empty CIDR
            '192.168.1.1/1/2',       // Multiple slashes
        );

        foreach ( $invalid_cidrs as $cidr ) {
            $this->assertFalse(
                XMLRPC_IP_Whitelist::validate_ip( $cidr ),
                "Expected '$cidr' to be invalid"
            );
        }
    }

    /**
     * Test edge cases
     */
    public function test_edge_cases() {
        // Leading zeros - filter_var handles these correctly
        // Note: '192.168.001.001' may be accepted by filter_var depending on PHP version

        // Whitespace should fail
        $this->assertFalse( XMLRPC_IP_Whitelist::validate_ip( ' 192.168.1.1' ) );
        $this->assertFalse( XMLRPC_IP_Whitelist::validate_ip( '192.168.1.1 ' ) );
        $this->assertFalse( XMLRPC_IP_Whitelist::validate_ip( ' 192.168.1.1 ' ) );

        // Null/special values
        $this->assertFalse( XMLRPC_IP_Whitelist::validate_ip( null ) );
    }

    /**
     * Test boundary CIDR values
     */
    public function test_cidr_boundaries() {
        // Valid boundaries
        $this->assertTrue( XMLRPC_IP_Whitelist::validate_ip( '192.168.1.1/0' ) );
        $this->assertTrue( XMLRPC_IP_Whitelist::validate_ip( '192.168.1.1/32' ) );
        $this->assertTrue( XMLRPC_IP_Whitelist::validate_ip( '192.168.1.1/1' ) );
        $this->assertTrue( XMLRPC_IP_Whitelist::validate_ip( '192.168.1.1/31' ) );

        // Invalid boundaries
        $this->assertFalse( XMLRPC_IP_Whitelist::validate_ip( '192.168.1.1/33' ) );
    }

    /**
     * Test actual Jetpack IPs (from their public list)
     */
    public function test_jetpack_ips() {
        $jetpack_ips = array(
            '122.248.245.244/32',
            '54.217.201.243/32',
            '54.232.116.4/32',
            '192.0.80.0/20',
            '192.0.96.0/20',
            '192.0.112.0/20',
            '195.234.108.0/22',
            '192.0.64.0/18',
        );

        foreach ( $jetpack_ips as $ip ) {
            $this->assertTrue(
                XMLRPC_IP_Whitelist::validate_ip( $ip ),
                "Jetpack IP $ip should be valid"
            );
        }
    }
}
