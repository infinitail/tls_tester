#!/bin/php
<?php
/**
 * Mail server STARTTLS cipher suite checker
 * for CentOS 7/8
 */

 // Init
if ($argc === 1) {
    $script_name = $_SERVER['PHP_SELF'];
    echo "Usage: {$script_name} target_server:port [my_hostname]".PHP_EOL;
    die();
}

// Check target server
@list($server, $port) = @explode(':', $argv[1]);
if (empty($server) || empty($port) || !is_numeric($port)) {
    echo 'Invalid target_server:port is specified!'.PHP_EOL;
    die();
}

// ELHO hostname
$hostname = ($argc === 2) ? gethostname() : $argv[2];

// Define cipher suite list by "$ openssl ciphers -v 'ALL:eNULL'"
exec("openssl ciphers -v 'ALL:eNULL'", $ciphers, $result);
if ($result !== 0) {
    die('Failed to excute OpenSSL command!');
}

// Define crypt methods
$methods = [
    //'ANY' => STREAM_CRYPTO_METHOD_ANY_CLIENT,         // 63
    //'SSL' => STREAM_CRYPTO_METHOD_SSLv23_CLIENT,      // 57
    //'TLS' => STREAM_CRYPTO_METHOD_TLS_CLIENT,         // 57
    //'SSLv2' => STREAM_CRYPTO_METHOD_SSLv2_CLIENT,     // 3    // no longer work properly
    'SSLv3'   => STREAM_CRYPTO_METHOD_SSLv3_CLIENT,     // 5
    'TLSv1'   => STREAM_CRYPTO_METHOD_TLSv1_0_CLIENT,   // 9
    'TLSv1.1' => STREAM_CRYPTO_METHOD_TLSv1_1_CLIENT,   // 17
    'TLSv1.2' => STREAM_CRYPTO_METHOD_TLSv1_2_CLIENT,   // 33
];

// Add if PHP/OpenSSL not support TLSv1.3
if (defined('STREAM_CRYPTO_METHOD_TLSv1_3_CLIENT')) {
    $methods['TLSv1.3'] = STREAM_CRYPTO_METHOD_TLSv1_3_CLIENT;    // 65
}

// Define WEAK ciphers
$weak_ciphers = [
    'au' => [
        'Au=None',
    ],
    'enc' => [
        'Enc=RC4(128)',
        'Enc=3DES(168)',
        'Enc=None',
    ],
    'mac' => [
        'Mac=MD5',
    ]
];

// Define WEAK crypt methods
$weak_methods = [
    'SSLv2', 'SSLv3', 'TLSv1',
];

// Test transport
$context = stream_context_create([
    'ssl' => [
        'verify_peer' => false,
        'verify_peer_name' => false,
        'allow_self_signed' => true,
    ],
]);

$transport = '';
echo "Start trying STARTTLS connection... ";
$conn = stream_socket_client("tcp://{$server}:{$port}", $errno, $errstr, 5,
            STREAM_CLIENT_CONNECT, $context);

if (!$conn) {
    die('SMTP server connection Error!'.PHP_EOL);
} else {
    stream_set_timeout($conn, 1);

    // Start TLS session after negotiate STARTTLS procedure
    $message = stream_get_contents($conn);
    if (empty($message)) {
        echo 'No Response!'.PHP_EOL;
    } else {
        echo 'Success'.PHP_EOL;
        $transport = 'tcp';
    }
    fclose($conn);
}

if (empty($transport)) {
    echo "Start trying TLS connection...\t";
    $conn = stream_socket_client("tls://{$server}:{$port}", $errno, $errstr, 5,
                STREAM_CLIENT_CONNECT, $context);

    if (!$conn) {
        die('SMTP server connection Error!'.PHP_EOL);
    } else {
        stream_set_timeout($conn, 1);

        // Start TLS session after negotiate STARTTLS procedure
        $message = stream_get_contents($conn);
        if (empty($message)) {
            echo 'No Response!'.PHP_EOL;
        } else {
            echo 'Success'.PHP_EOL;
            $transport = 'tls';
        }
    }
}

if ($transport === 'tls') {
    die('Use TLS version tester!'.PHP_EOL);
}

// Start server check
// Cipher suite loop
foreach ($ciphers as $cipher_set) {
    $cipher_set = trim($cipher_set);
    list($cipher, $proto, $kx, $au, $enc, $mac) = preg_split('/\s+/', $cipher_set);

    // Encrypt method loop
    foreach ($methods as $key => $method) {
        // Skip if cipher suite does not supported by crypt method
        if (!isset($methods[$proto]) || $methods[$proto] > $methods[$key]) {
            continue;
        }

        $context = stream_context_create([
            'ssl' => [
                'ciphers' => $cipher,
                'crypto_method' => $method,
                'capture_session_meta' => true,
                'capture_peer_cert' => true,
                'SNI_enabled' => true,
                'single_dh_use' => true,
                'single_ecdh_use' => true,
                'verify_peer' => false,
                'verify_peer_name' => false,
                'allow_self_signed' => true,
            ],
        ]);

        $conn = @stream_socket_client("{$transport}://{$server}:{$port}", $errno, $errstr, 5,
            STREAM_CLIENT_CONNECT, $context);
        if (!$conn) {
            die('SMTP server connection Error!'.PHP_EOL);
        } else {
            stream_set_timeout($conn, 1);

            // Start TLS session after negotiate STARTTLS procedure
            $message = stream_get_contents($conn);
            fwrite($conn, "EHLO {$hostname}\n");
            $message = stream_get_contents($conn);
            if (strpos($message, 'STARTTLS') === false) {
                die('This SMTP server does not support STARTTLS!'.PHP_EOL);
            }

            fwrite($conn, "STARTTLS\n");
            $message = stream_get_contents($conn);
            if (strpos($message, '220 2.0.0 Ready to start TLS') === false) {
                die('Can not confirm ACK of STARTTLS'.PHP_EOL);
            }

            $tls = @stream_socket_enable_crypto($conn, true, $method);


            if ($tls === false) {
                // failed to start TLS session
                echo "\e[31m$cipher - $key: NG\e[39m".PHP_EOL;
            } else {
                // Start TLS session OK
                // Get really selected protocol
                $real_proto = stream_get_meta_data($conn)['crypto']['protocol'];
                $proto_message = ($real_proto !== $key) ? " ({$real_proto})" : '';

                // Check WEAK ciphers and protocols
                $weak = '';
                if (in_array($au, $weak_ciphers['au']) ||
                    in_array($enc, $weak_ciphers['enc']) ||
                    in_array($mac, $weak_ciphers['mac'])) {
                    $weak .= "\e[31m[WEAK cipher]\e[39m ";
                }
                if (in_array($real_proto, $weak_methods)) {
                    $weak .= "\e[31m[WEAK protocol]\e[39m ";
                }

                // Display selected cipher suite
                echo "\e[32m{$cipher} - {$key}{$proto_message}: OK\e[39m {$weak}".PHP_EOL;

                //$cert = stream_context_get_options($conn)['ssl']['peer_certificate'];
                //$key  = openssl_pkey_get_public($cert);
                //$res = openssl_pkey_get_details($key);
                //var_dump($res['bits']);
            }
            fclose($conn);
        }

        unset($conn);
        unset($context);
    }
    sleep(1);
}



