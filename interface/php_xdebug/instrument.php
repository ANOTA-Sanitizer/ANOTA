<?php
/**
 * MAC-DAST Xdebug Instrumentation Helper
 * 
 * This file is intended to be auto-prepended to PHP executions to capture
 * code coverage, session state, and request context.
 */

if (!function_exists('xdebug_start_code_coverage')) {
    fwrite(STDERR, "Error: Xdebug extension not loaded. Coverage will not be collected.\n");
    return;
}

xdebug_start_code_coverage(XDEBUG_CC_UNUSED | XDEBUG_CC_DEAD_CODE);

register_shutdown_function(function() {
    $coverage = xdebug_get_code_coverage();
    xdebug_stop_code_coverage();
    
    // Capture Full Context
    $state = [
        "session" => isset($_SESSION) ? $_SESSION : [],
        "cookies" => $_COOKIE,
        "get" => $_GET,
        "post" => $_POST,
        "server" => [
            "REQUEST_METHOD" => $_SERVER["REQUEST_METHOD"] ?? "CLI",
            "REQUEST_URI" => $_SERVER["REQUEST_URI"] ?? "",
            "PHP_SELF" => $_SERVER["PHP_SELF"] ?? ""
        ],
        "headers_out" => headers_list()
    ];

    $telemetry = [
        "type" => "telemetry",
        "coverage" => $coverage,
        "state" => $state
    ];

    // 1. Try sending to socket if requested via env
    $socket_path = getenv("ANOTA_OBSERVER_SOCKET");
    if ($socket_path) {
        $fp = @stream_socket_client("unix://$socket_path", $errno, $errstr, 1);
        if ($fp) {
            fwrite($fp, json_encode($telemetry));
            fclose($fp);
            return; // Success
        }
    }

    // 2. Fallback to file if requested via env
    $target = getenv("ANOTA_TELEMETRY_TARGET");
    if ($target && $target !== "stdout") {
        file_put_contents($target, json_encode($telemetry));
    } else {
        // 3. Fallback to stdout with markers
        echo "\n---ANOTA_TELEMETRY_START---\n";
        echo json_encode($telemetry);
        echo "\n---ANOTA_TELEMETRY_END---\n";
    }
});
?>
