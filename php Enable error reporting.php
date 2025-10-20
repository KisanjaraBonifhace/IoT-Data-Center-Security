<?php
// ===================== PHP Code Starts Here =====================
error_reporting(E_ALL);
ini_set('display_errors', 1);
session_start();

// Database connection
$db = new mysqli("sql300.infinityfree.com", "if0_38474310", "YAQn0LSi4Pg", "if0_38474310_admins_login");
if ($db->connect_error) {
    die("Database connection failed: " . $db->connect_error);
}

// Pushover credentials
define('PUSHOVER_USER', 'ubgyefoah576axintozbu33nm9dh22');
define('PUSHOVER_TOKEN', 'aa46811afwn3wezn1vb4mpfaw9kiis');

// Admin credentials to be created initially
$adminUsers = [
    ['username' => 'kisanjara', 'password' => 'malware800'],
    ['username' => 'agnetha', 'password' => 'admins123']
];

// ========== TABLE CREATION ==========
$tables = [
    "CREATE TABLE IF NOT EXISTS admin_users (
        id INT AUTO_INCREMENT PRIMARY KEY,
        username VARCHAR(255) UNIQUE NOT NULL,
        password VARCHAR(255) NOT NULL
    ) ENGINE=InnoDB",

    "CREATE TABLE IF NOT EXISTS temperature_logs (
        id INT AUTO_INCREMENT PRIMARY KEY,
        temperature FLOAT NOT NULL,
        status VARCHAR(20) NOT NULL,
        timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
    ) ENGINE=InnoDB",

    "CREATE TABLE IF NOT EXISTS security_alerts (
        id INT AUTO_INCREMENT PRIMARY KEY,
        alert_type VARCHAR(50) NOT NULL,
        message TEXT NOT NULL,
        severity VARCHAR(20) NOT NULL,
        timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
    ) ENGINE=InnoDB",

    "CREATE TABLE IF NOT EXISTS login_attempts (
        id INT AUTO_INCREMENT PRIMARY KEY,
        username VARCHAR(255),
        ip_address VARCHAR(45) NOT NULL,
        attempts INT DEFAULT 1,
        last_attempt TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        locked_until TIMESTAMP NULL,
        UNIQUE KEY unique_ip_user (ip_address, username)
    ) ENGINE=InnoDB",

    "CREATE TABLE IF NOT EXISTS banned_ips (
        id INT AUTO_INCREMENT PRIMARY KEY,
        ip_address VARCHAR(45) UNIQUE NOT NULL,
        banned_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        banned_by VARCHAR(255),
        reason VARCHAR(255),
        attempts INT DEFAULT 0,
        is_permanent BOOLEAN DEFAULT TRUE
    ) ENGINE=InnoDB"
];

foreach ($tables as $sql) {
    if (!$db->query($sql)) {
        die("Error creating table: " . $db->error);
    }
}

// ========== CREATE ADMIN USERS IF NOT EXISTS ==========
foreach ($adminUsers as $admin) {
    $check = $db->prepare("SELECT id FROM admin_users WHERE username = ?");
    $check->bind_param('s', $admin['username']);
    $check->execute();
    $check->store_result();
    if ($check->num_rows === 0) {
        $hashedPassword = password_hash($admin['password'], PASSWORD_DEFAULT);
        $stmt = $db->prepare("INSERT INTO admin_users (username, password) VALUES (?, ?)");
        $stmt->bind_param('ss', $admin['username'], $hashedPassword);
        $stmt->execute();
    }
    $check->close();
}

// ========== LIVE TEMPERATURE ENDPOINT ==========
if (isset($_GET['live_temp'])) {
    // Get latest temperature reading
    $result = $db->query("SELECT temperature, status, timestamp FROM temperature_logs ORDER BY timestamp DESC LIMIT 1");
    $reading = $result->fetch_assoc();
    
    header('Content-Type: application/json');
    echo json_encode([
        'temperature' => $reading['temperature'] ?? null,
        'status' => $reading['status'] ?? 'N/A',
        'timestamp' => $reading['timestamp'] ?? null
    ]);
    exit();
}

// ========== MANUAL TEMPERATURE READING ENDPOINT ==========
if (isset($_GET['manual_reading']) && isset($_GET['temp']) && isset($_SESSION['logged_in'])) {
    $temperature = (float)$_GET['temp'];
    $status = 'NORMAL';
    
    if ($temperature > 60) {
        $status = 'CRITICAL';
    } elseif ($temperature > 40) {
        $status = 'WARNING';
    }
    
    $stmt = $db->prepare("INSERT INTO temperature_logs (temperature, status) VALUES (?, ?)");
    $stmt->bind_param('ds', $temperature, $status);
    $stmt->execute();
    
    header('Content-Type: application/json');
    echo json_encode(['success' => true, 'message' => 'Manual reading recorded']);
    exit();
}

// ========== IP BANNED CHECK ==========
$ip = $_SERVER['REMOTE_ADDR'];
$banCheck = $db->prepare("SELECT * FROM banned_ips WHERE ip_address = ?");
$banCheck->bind_param('s', $ip);
$banCheck->execute();
$banned = $banCheck->get_result()->fetch_assoc();
$banCheck->close();

// ========== HANDLE UNBAN ==========
if (isset($_GET['unban_ip']) && isset($_SESSION['logged_in'])) {
    $ipToUnban = $_GET['unban_ip'];

    $check = $db->prepare("SELECT * FROM banned_ips WHERE ip_address = ?");
    $check->bind_param('s', $ipToUnban);
    $check->execute();
    $found = $check->get_result()->fetch_assoc();
    $check->close();

    if ($found) {
        $db->prepare("DELETE FROM banned_ips WHERE ip_address = ?")->bind_param('s', $ipToUnban)->execute();
        $db->prepare("DELETE FROM login_attempts WHERE ip_address = ?")->bind_param('s', $ipToUnban)->execute();

        $msg = "IP $ipToUnban unbanned by " . $_SESSION['username'];
        $stmt = $db->prepare("INSERT INTO security_alerts (alert_type, message, severity) VALUES ('IP Unbanned', ?, 'low')");
        $stmt->bind_param('s', $msg);
        $stmt->execute();

        $_SESSION['message'] = "IP $ipToUnban unbanned successfully.";
    } else {
        $_SESSION['message'] = "IP $ipToUnban was not found.";
    }

    header("Location: " . strtok($_SERVER['REQUEST_URI'], '?'));
    exit();
}

// ========== LOGOUT ==========
if (isset($_GET['logout'])) {
    session_unset();
    session_destroy();
    header("Location: " . strtok($_SERVER['REQUEST_URI'], '?'));
    exit();
}

// ========== REPORT DOWNLOAD ==========
if (isset($_GET['download_report']) && isset($_SESSION['logged_in'])) {
    $reportType = $_GET['report_type'] ?? 'temperature';
    $dateFrom = $_GET['date_from'] ?? date('Y-m-d', strtotime('-7 days'));
    $dateTo = $_GET['date_to'] ?? date('Y-m-d');
    
    // Validate dates
    if (!strtotime($dateFrom) || !strtotime($dateTo)) {
        $_SESSION['message'] = "Invalid date format. Please use YYYY-MM-DD.";
        header("Location: " . strtok($_SERVER['REQUEST_URI'], '?'));
        exit();
    }
    
    // Prepare report data
    switch ($reportType) {
        case 'temperature':
            $query = "SELECT id, temperature, status, timestamp 
                      FROM temperature_logs 
                      WHERE DATE(timestamp) BETWEEN ? AND ? 
                      ORDER BY timestamp DESC";
            $filename = "temperature_report_" . date('Ymd_His') . ".csv";
            $headers = ['ID', 'Temperature (°C)', 'Status', 'Timestamp'];
            break;
            
        case 'security':
            $query = "SELECT id, alert_type, message, severity, timestamp 
                      FROM security_alerts 
                      WHERE DATE(timestamp) BETWEEN ? AND ? 
                      ORDER BY timestamp DESC";
            $filename = "security_report_" . date('Ymd_His') . ".csv";
            $headers = ['ID', 'Alert Type', 'Message', 'Severity', 'Timestamp'];
            break;
            
        case 'login_attempts':
            $query = "SELECT id, username, ip_address, attempts, last_attempt, locked_until 
                      FROM login_attempts 
                      WHERE DATE(last_attempt) BETWEEN ? AND ? 
                      ORDER BY last_attempt DESC";
            $filename = "login_attempts_report_" . date('Ymd_His') . ".csv";
            $headers = ['ID', 'Username', 'IP Address', 'Attempts', 'Last Attempt', 'Locked Until'];
            break;
            
        case 'banned_ips':
            $query = "SELECT ip_address, banned_at, reason, attempts, is_permanent, banned_by 
                      FROM banned_ips 
                      WHERE DATE(banned_at) BETWEEN ? AND ? 
                      ORDER BY banned_at DESC";
            $filename = "banned_ips_report_" . date('Ymd_His') . ".csv";
            $headers = ['IP Address', 'Banned At', 'Reason', 'Attempts', 'Is Permanent', 'Banned By'];
            break;
            
        default:
            $_SESSION['message'] = "Invalid report type selected.";
            header("Location: " . strtok($_SERVER['REQUEST_URI'], '?'));
            exit();
    }
    
    // Prepare and execute query
    $stmt = $db->prepare($query);
    if (!$stmt) {
        die("Error preparing query: " . $db->error);
    }
    
    $stmt->bind_param('ss', $dateFrom, $dateTo);
    if (!$stmt->execute()) {
        die("Error executing query: " . $stmt->error);
    }
    
    $result = $stmt->get_result();
    
    // Generate CSV
    header('Content-Type: text/csv; charset=utf-8');
    header('Content-Disposition: attachment; filename="' . $filename . '"');
    
    $output = fopen('php://output', 'w');
    
    // Add BOM for UTF-8 compatibility with Excel
    fwrite($output, "\xEF\xBB\xBF");
    
    // Write headers
    fputcsv($output, $headers);
    
    // Write data rows
    while ($row = $result->fetch_assoc()) {
        // Format boolean values
        if (isset($row['is_permanent'])) {
            $row['is_permanent'] = $row['is_permanent'] ? 'Yes' : 'No';
        }
        
        // Format timestamps
        if (isset($row['timestamp'])) {
            $row['timestamp'] = date('Y-m-d H:i:s', strtotime($row['timestamp']));
        }
        if (isset($row['last_attempt'])) {
            $row['last_attempt'] = date('Y-m-d H:i:s', strtotime($row['last_attempt']));
        }
        if (isset($row['banned_at'])) {
            $row['banned_at'] = date('Y-m-d H:i:s', strtotime($row['banned_at']));
        }
        if (isset($row['locked_until'])) {
            $row['locked_until'] = $row['locked_until'] ? date('Y-m-d H:i:s', strtotime($row['locked_until'])) : 'Not locked';
        }
        
        fputcsv($output, $row);
    }
    
    fclose($output);
    exit();
}

// ========== IF BANNED ==========
if ($banned && !isset($_SESSION['logged_in'])) {
    $_SESSION['login_error'] = "Your IP address ($ip) has been banned. Please visit your administrator.";
    if (file_exists('login_page.php')) {
        include_once 'login_page.php';
    } else {
        echo "<h2>Your IP address ($ip) has been banned. Please visit your administrator.</h2>";
    }
    exit();
}

// ========== LOGIN PROCESS ==========
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['username'])) {
    $username = trim($_POST['username']);
    $password = trim($_POST['password']);

    // Check if IP is banned
    if ($banned) {
        $_SESSION['login_error'] = "Your IP address ($ip) has been banned. Please visit your administrator.";
        header("Location: " . $_SERVER['PHP_SELF']);
        exit();
    }

    $check = $db->prepare("SELECT * FROM admin_users WHERE username = ?");
    $check->bind_param('s', $username);
    $check->execute();
    $user = $check->get_result()->fetch_assoc();
    $check->close();

    if ($user && password_verify($password, $user['password'])) {
        // Successful login
        $stmt = $db->prepare("DELETE FROM login_attempts WHERE ip_address = ? AND username = ?");
        $stmt->bind_param('ss', $ip, $username);
        $stmt->execute();

        $_SESSION['logged_in'] = true;
        $_SESSION['username'] = $username;

        sendPushoverNotification(PUSHOVER_USER, PUSHOVER_TOKEN, "Login Success: $username from IP $ip");

        header("Location: " . $_SERVER['PHP_SELF']);
        exit();
    } else {
        // Failed login
        $stmt = $db->prepare("SELECT attempts FROM login_attempts WHERE ip_address = ? AND username = ?");
        $stmt->bind_param('ss', $ip, $username);
        $stmt->execute();
        $row = $stmt->get_result()->fetch_assoc();
        $stmt->close();

        $attempts = $row['attempts'] ?? 0;
        $newAttempts = $attempts + 1;

        // Update or insert login attempt
        $stmt = $db->prepare("INSERT INTO login_attempts (username, ip_address, attempts) 
                              VALUES (?, ?, 1)
                              ON DUPLICATE KEY UPDATE attempts = attempts + 1, last_attempt = CURRENT_TIMESTAMP");
        $stmt->bind_param('ss', $username, $ip);
        $stmt->execute();

        // Show attempt count
        $_SESSION['login_error'] = "Invalid credentials. Failed login attempt $newAttempts/5";
        
        if ($newAttempts >= 5) {
            // Ban the IP after 5 attempts
            $reason = "5 failed login attempts for $username";
            $admin = $_SESSION['username'] ?? 'system';

            $stmt = $db->prepare("INSERT INTO banned_ips (ip_address, banned_by, reason, attempts, is_permanent) 
                                  VALUES (?, ?, ?, ?, TRUE)
                                  ON DUPLICATE KEY UPDATE attempts = ?, banned_at = CURRENT_TIMESTAMP");
            $stmt->bind_param('sssii', $ip, $admin, $reason, $newAttempts, $newAttempts);
            $stmt->execute();

            $alert = "IP $ip permanently banned after 5 failed login attempts for $username.";
            $db->query("INSERT INTO security_alerts (alert_type, message, severity) VALUES 
                        ('Brute Force Attempt', '$alert', 'high')");
            sendPushoverNotification(PUSHOVER_USER, PUSHOVER_TOKEN, $alert);

            $_SESSION['login_error'] = "Your IP address ($ip) has been banned. Please visit your administrator.";
        }

        header("Location: " . $_SERVER['PHP_SELF']);
        exit();
    }
}

// ========== RABBITMQ CONFIGURATION ==========
define('RABBITMQ_HOST', '192.168.1.169');
define('RABBITMQ_PORT', 5672);
define('RABBITMQ_USER', 'admin');
define('RABBITMQ_PASS', 'admin');
define('RABBITMQ_VHOST', '/');
define('RABBITMQ_QUEUE', 'temperature_readings');
define('RABBITMQ_EXCHANGE', 'amq.direct');

// ========== RABBITMQ CONSUMER FUNCTION ==========
function consumeRabbitMQMessages() {
    try {
        $connection = new AMQPConnection([
            'host' => RABBITMQ_HOST,
            'port' => RABBITMQ_PORT,
            'vhost' => RABBITMQ_VHOST,
            'login' => RABBITMQ_USER,
            'password' => RABBITMQ_PASS
        ]);
        
        if (!$connection->connect()) {
            throw new Exception("Cannot connect to RabbitMQ server");
        }
        
        $channel = new AMQPChannel($connection);
        $queue = new AMQPQueue($channel);
        $queue->setName(RABBITMQ_QUEUE);
        $queue->declareQueue();
        $queue->bind(RABBITMQ_EXCHANGE, RABBITMQ_QUEUE);
        
        $callback = function(AMQPEnvelope $message) {
            global $db;
            
            $body = $message->getBody();
            $data = json_decode($body, true);
            
            if (isset($data['temperature'])) {
                $temperature = (float)$data['temperature'];
                $status = 'NORMAL';
                
                if ($temperature > 60) {
                    $status = 'CRITICAL';
                    $alertType = 'High Temperature Alert';
                    $severity = 'high';
                } elseif ($temperature > 40) {
                    $status = 'WARNING';
                    $alertType = 'Warning Temperature Alert';
                    $severity = 'medium';
                }
                
                // Insert into temperature logs
                $stmt = $db->prepare("INSERT INTO temperature_logs (temperature, status) VALUES (?, ?)");
                $stmt->bind_param('ds', $temperature, $status);
                $stmt->execute();
                
                // Create security alert if needed
                if ($status !== 'NORMAL') {
                    $alertMessage = "Temperature Alert: $temperature°C (Status: $status)";
                    $stmt = $db->prepare("INSERT INTO security_alerts (alert_type, message, severity) VALUES (?, ?, ?)");
                    $stmt->bind_param('sss', $alertType, $alertMessage, $severity);
                    $stmt->execute();
                    
                    sendPushoverNotification(PUSHOVER_USER, PUSHOVER_TOKEN, $alertMessage);
                }
                
                return true; // Acknowledge message
            }
            
            return false; // Reject message
        };
        
        $queue->consume($callback);
        $connection->disconnect();
    } catch (Exception $e) {
        error_log("RabbitMQ Consumer Error: " . $e->getMessage());
        return false;
    }
}

// ========== RABBITMQ PUBLISHER FUNCTION ==========
function publishToRabbitMQ($data) {
    try {
        $connection = new AMQPConnection([
            'host' => RABBITMQ_HOST,
            'port' => RABBITMQ_PORT,
            'vhost' => RABBITMQ_VHOST,
            'login' => RABBITMQ_USER,
            'password' => RABBITMQ_PASS
        ]);
        
        if (!$connection->connect()) {
            throw new Exception("Cannot connect to RabbitMQ server");
        }
        
        $channel = new AMQPChannel($connection);
        $exchange = new AMQPExchange($channel);
        $exchange->setName(RABBITMQ_EXCHANGE);
        $exchange->setType(AMQP_EX_TYPE_DIRECT);
        $exchange->declareExchange();
        
        $result = $exchange->publish(
            json_encode($data),
            RABBITMQ_QUEUE,
            AMQP_NOPARAM,
            ['delivery_mode' => 2] // Persistent message
        );
        
        $connection->disconnect();
        return $result;
    } catch (Exception $e) {
        error_log("RabbitMQ Publisher Error: " . $e->getMessage());
        return false;
    }
}

// ========== HANDLE RABBITMQ SYNC REQUEST ==========
if (isset($_GET['sync_rabbitmq']) && isset($_SESSION['logged_in'])) {
    $execAvailable = function_exists('exec') && !in_array('exec', array_map('trim', explode(',', ini_get('disable_functions'))));
    
    if ($execAvailable) {
        // Try to start consumer in background
        $output = null;
        $result = null;
        @exec("php rabbitmq_consumer.php > /dev/null 2>&1 &", $output, $result);
        
        if ($result === 0) {
            $_SESSION['message'] = "RabbitMQ consumer started in background";
        } else {
            $_SESSION['message'] = "Failed to start RabbitMQ consumer. Error code: $result";
            $_SESSION['message'] .= "<br>Please try running it manually:";
            $_SESSION['message'] .= "<pre>php rabbitmq_consumer.php</pre>";
        }
    } else {
        $_SESSION['message'] = "The exec() function is disabled on this server. ";
        $_SESSION['message'] .= "Please run the RabbitMQ consumer manually with:";
        $_SESSION['message'] .= "<pre>php rabbitmq_consumer.php</pre>";
        $_SESSION['message'] .= "<p>For persistent operation, consider setting up a cron job or systemd service.</p>";
    }
    
    header("Location: " . strtok($_SERVER['REQUEST_URI'], '?'));
    exit();
}

// ========== SEND HISTORICAL DATA TO RABBITMQ ==========
if (isset($_GET['send_history']) && isset($_SESSION['logged_in'])) {
    $limit = min(100, (int)($_GET['limit'] ?? 10));
    $logs = $db->query("SELECT * FROM temperature_logs ORDER BY timestamp DESC LIMIT $limit");
    
    $count = 0;
    while ($row = $logs->fetch_assoc()) {
        $data = [
            'temperature' => $row['temperature'],
            'status' => $row['status'],
            'timestamp' => $row['timestamp']
        ];
        if (publishToRabbitMQ($data)) {
            $count++;
        }
    }
    
    $_SESSION['message'] = "Sent $count historical records to RabbitMQ";
    header("Location: " . strtok($_SERVER['REQUEST_URI'], '?'));
    exit();
}

// ========== PUSHOVER FUNCTION ==========
function sendPushoverNotification($userKey, $apiToken, $message) {
    $data = [
        'user' => $userKey,
        'token' => $apiToken,
        'message' => $message
    ];
    $ch = curl_init('https://api.pushover.net:443/1/messages.json');
    curl_setopt($ch, CURLOPT_POST, true);
    curl_setopt($ch, CURLOPT_POSTFIELDS, http_build_query($data));
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
    curl_exec($ch);
    curl_close($ch);
}
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>IoT Security Dashboard</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
    <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap-icons@1.11.0/font/bootstrap-icons.css">
    <style>
        :root {
            --primary-bg: linear-gradient(135deg, #83a4d4, #b6fbff);
            --card-shadow: 0 4px 6px rgba(0, 0, 0, 0.1);
            --status-normal: #28a745;
            --status-warning: #ffc107;
            --status-danger: #dc3545;
        }
        body {
            background: var(--primary-bg);
            min-height: 100vh;
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
        }
        .login-box {
            max-width: 400px;
            margin: 100px auto;
            background: white;
            padding: 2rem;
            border-radius: 10px;
            box-shadow: var(--card-shadow);
        }
        .dashboard {
            margin-top: 2rem;
            padding-bottom: 2rem;
        }
        .card {
            margin-bottom: 1.5rem;
            box-shadow: var(--card-shadow);
            border: none;
            transition: transform 0.2s;
        }
        .card:hover {
            transform: translateY(-5px);
        }
        .card-header {
            font-weight: 600;
        }
        .temperature-display {
            font-size: 2.5rem;
            font-weight: bold;
        }
        .status-normal { color: var(--status-normal); }
        .status-warning { color: var(--status-warning); }
        .status-danger { color: var(--status-danger); }
        .severity-high { color: var(--status-danger); font-weight: bold; }
        .severity-medium { color: var(--status-warning); }
        .severity-low { color: #6c757d; }
        .nav-tabs .nav-link.active {
            font-weight: bold;
            border-bottom: 3px solid var(--status-normal);
        }
        .alert-badge {
            position: absolute;
            top: -10px;
            right: -10px;
            font-size: 0.75rem;
        }
        .real-time-badge {
            animation: pulse 2s infinite;
        }
        .ban-reason {
            font-size: 0.85rem;
            color: #6c757d;
        }
        .permanent-ban {
            color: #dc3545;
            font-weight: bold;
        }
        .report-form {
            background: white;
            padding: 1.5rem;
            border-radius: 8px;
            box-shadow: var(--card-shadow);
            margin-bottom: 2rem;
        }
        pre {
            background: #f8f9fa;
            padding: 10px;
            border-radius: 5px;
            border: 1px solid #dee2e6;
        }
        @keyframes pulse {
            0% { opacity: 1; }
            50% { opacity: 0.5; }
            100% { opacity: 1; }
        }
    </style>
</head>
<body>
<?php if (!isset($_SESSION['logged_in'])): ?>
    <div class="login-box">
        <div class="text-center mb-4">
            <i class="bi bi-shield-lock" style="font-size: 2.5rem; color: #83a4d4;"></i>
            <h3 class="text-primary mt-2">IoT Security Dashboard</h3>
        </div>
        <?php if (isset($_SESSION['login_error'])): ?>
            <div class="alert alert-danger alert-dismissible fade show">
                <?= htmlspecialchars($_SESSION['login_error']) ?>
                <button type="button" class="btn-close" data-bs-dismiss="alert"></button>
            </div>
            <?php unset($_SESSION['login_error']); ?>
        <?php endif; ?>
        <form method="POST" action="">
            <div class="mb-3">
                <label class="form-label">Username</label>
                <div class="input-group">
                    <span class="input-group-text"><i class="bi bi-person"></i></span>
                    <input type="text" name="username" class="form-control" required autofocus>
                </div>
            </div>
            <div class="mb-3">
                <label class="form-label">Password</label>
                <div class="input-group">
                    <span class="input-group-text"><i class="bi bi-lock"></i></span>
                    <input type="password" name="password" class="form-control" required>
                </div>
            </div>
            <button type="submit" class="btn btn-primary w-100 py-2">
                <i class="bi bi-box-arrow-in-right"></i> Login
            </button>
        </form>
    </div>
<?php else: ?>
    <nav class="navbar navbar-expand-lg navbar-dark bg-dark">
        <div class="container-fluid">
            <a class="navbar-brand" href="#">
                <i class="bi bi-shield-lock me-2"></i>IoT Security Dashboard
            </a>
            <div class="d-flex align-items-center">
                <span class="navbar-text me-3 d-none d-sm-inline">
                    <i class="bi bi-person-circle me-1"></i><?= htmlspecialchars($_SESSION['username']) ?>
                </span>
                <div class="btn-group">
                    <button type="button" class="btn btn-success dropdown-toggle" data-bs-toggle="dropdown">
                        <i class="bi bi-download"></i> Export
                    </button>
                    <ul class="dropdown-menu">
                        <li><a class="dropdown-item" href="?download_report=1&report_type=temperature">Temperature Data</a></li>
                        <li><a class="dropdown-item" href="?download_report=1&report_type=security">Security Alerts</a></li>
                        <li><a class="dropdown-item" href="?download_report=1&report_type=login_attempts">Login Attempts</a></li>
                        <li><a class="dropdown-item" href="?download_report=1&report_type=banned_ips">Banned IPs</a></li>
                    </ul>
                    <a href="?logout=1" class="btn btn-danger">
                        <i class="bi bi-box-arrow-right"></i> Logout
                    </a>
                </div>
            </div>
        </div>
    </nav>
    
    <div class="container dashboard">
        <?php if (isset($_SESSION['message'])): ?>
            <div class="alert alert-info alert-dismissible fade show mt-3">
                <?= $_SESSION['message'] ?>
                <button type="button" class="btn-close" data-bs-dismiss="alert"></button>
            </div>
            <?php unset($_SESSION['message']); ?>
        <?php endif; ?>
        
        <!-- Report Download Form -->
        <div class="report-form">
            <h4><i class="bi bi-download me-2"></i>Generate Report</h4>
            <form method="get" action="">
                <input type="hidden" name="download_report" value="1">
                <div class="row g-3">
                    <div class="col-md-4">
                        <label class="form-label">Report Type</label>
                        <select name="report_type" class="form-select">
                            <option value="temperature">Temperature Data</option>
                            <option value="security">Security Alerts</option>
                            <option value="login_attempts">Login Attempts</option>
                            <option value="banned_ips">Banned IPs</option>
                        </select>
                    </div>
                    <div class="col-md-3">
                        <label class="form-label">From Date</label>
                        <input type="date" name="date_from" class="form-control" 
                               value="<?= date('Y-m-d', strtotime('-7 days')) ?>">
                    </div>
                    <div class="col-md-3">
                        <label class="form-label">To Date</label>
                        <input type="date" name="date_to" class="form-control" 
                               value="<?= date('Y-m-d') ?>">
                    </div>
                    <div class="col-md-2 d-flex align-items-end">
                        <button type="submit" class="btn btn-primary w-100">
                            <i class="bi bi-download me-1"></i> Download
                        </button>
                    </div>
                </div>
            </form>
        </div>
        
        <div class="d-flex justify-content-between mb-3">
            <div>
                <button onclick="sendManualReading()" class="btn btn-info me-2">
                    <i class="bi bi-plus-circle"></i> Add Manual Reading
                </button>
                <a href="?sync_rabbitmq=1" class="btn btn-warning me-2">
                    <i class="bi bi-arrow-repeat"></i> Sync RabbitMQ
                </a>
                <a href="?send_history=1" class="btn btn-secondary">
                    <i class="bi bi-send"></i> Send History to RabbitMQ
                </a>
            </div>
        </div>
        
        <ul class="nav nav-tabs mb-4" id="dashboardTabs" role="tablist">
            <li class="nav-item" role="presentation">
                <button class="nav-link active" id="temperature-tab" data-bs-toggle="tab" data-bs-target="#temperature" type="button" role="tab">
                    <i class="bi bi-thermometer-half me-1"></i>Temperature
                </button>
            </li>
            <li class="nav-item" role="presentation">
                <button class="nav-link" id="alerts-tab" data-bs-toggle="tab" data-bs-target="#alerts" type="button" role="tab">
                    <i class="bi bi-exclamation-triangle me-1"></i>Security Alerts
                    <?php 
                    $alertCount = $db->query("SELECT COUNT(*) as count FROM security_alerts WHERE severity = 'high'")->fetch_assoc()['count'];
                    if ($alertCount > 0): ?>
                        <span class="badge bg-danger rounded-pill"><?= $alertCount ?></span>
                    <?php endif; ?>
                </button>
            </li>
            <li class="nav-item" role="presentation">
                <button class="nav-link" id="bans-tab" data-bs-toggle="tab" data-bs-target="#bans" type="button" role="tab">
                    <i class="bi bi-ban me-1"></i>IP Bans
                    <?php 
                    $banCount = $db->query("SELECT COUNT(*) as count FROM banned_ips")->fetch_assoc()['count'];
                    if ($banCount > 0): ?>
                        <span class="badge bg-warning rounded-pill"><?= $banCount ?></span>
                    <?php endif; ?>
                </button>
            </li>
        </ul>
        
        <div class="tab-content" id="dashboardTabsContent">
            <!-- Temperature Tab -->
            <div class="tab-pane fade show active" id="temperature" role="tabpanel">
                <div class="row">
                    <div class="col-md-6">
                        <div class="card">
                            <div class="card-header bg-info text-white d-flex justify-content-between align-items-center">
                                <h5 class="card-title mb-0">
                                    <i class="bi bi-thermometer-high me-1"></i>Live Temperature
                                </h5>
                                <span class="badge bg-light text-dark real-time-badge">LIVE</span>
                            </div>
                            <div class="card-body text-center">
                                <div class="temperature-display text-primary mb-2" id="live-temp">--.-</div>
                                <div class="text-muted">
                                    <span id="temp-status" class="badge status-normal">N/A</span>
                                    <span class="ms-2">Last updated: <span id="last-updated">Just now</span></span>
                                </div>
                            </div>
                        </div>
                    </div>
                    
                    <div class="col-md-6">
                        <div class="card">
                            <div class="card-header bg-secondary text-white">
                                <h5 class="card-title mb-0">
                                    <i class="bi bi-graph-up me-1"></i>Temperature Stats
                                </h5>
                            </div>
                            <div class="card-body">
                                <?php
                                $stats = $db->query("
                                    SELECT 
                                        MAX(temperature) as max_temp,
                                        MIN(temperature) as min_temp,
                                        AVG(temperature) as avg_temp,
                                        COUNT(*) as total_readings
                                    FROM temperature_logs
                                ")->fetch_assoc();
                                
                                $lastAlert = $db->query("
                                    SELECT alert_type, message, timestamp 
                                    FROM security_alerts 
                                    WHERE alert_type LIKE '%temperature%' 
                                    ORDER BY timestamp DESC 
                                    LIMIT 1
                                ")->fetch_assoc();
                                ?>
                                <div class="row">
                                    <div class="col-6 mb-3">
                                        <div class="fw-bold">Maximum</div>
                                        <div class="h4"><?= round($stats['max_temp'] ?? 0, 1) ?>°C</div>
                                    </div>
                                    <div class="col-6 mb-3">
                                        <div class="fw-bold">Minimum</div>
                                        <div class="h4"><?= round($stats['min_temp'] ?? 0, 1) ?>°C</div>
                                    </div>
                                    <div class="col-6">
                                        <div class="fw-bold">Average</div>
                                        <div class="h4"><?= round($stats['avg_temp'] ?? 0, 1) ?>°C</div>
                                    </div>
                                    <div class="col-6">
                                        <div class="fw-bold">Readings</div>
                                        <div class="h4"><?= $stats['total_readings'] ?? 0 ?></div>
                                    </div>
                                </div>
                                
                                <?php if ($lastAlert): ?>
                                    <hr>
                                    <div class="alert alert-warning p-2 mb-0">
                                        <div class="fw-bold">
                                            <i class="bi bi-exclamation-triangle-fill me-1"></i>
                                            Last Alert
                                        </div>
                                        <div class="small"><?= htmlspecialchars($lastAlert['message']) ?></div>
                                        <div class="text-muted small"><?= $lastAlert['timestamp'] ?></div>
                                    </div>
                                <?php endif; ?>
                            </div>
                        </div>
                    </div>
                </div>
                
                <div class="card mt-4">
                    <div class="card-header bg-secondary text-white">
                        <h5 class="card-title mb-0">
                            <i class="bi bi-clock-history me-1"></i>Temperature History
                        </h5>
                    </div>
                    <div class="card-body table-responsive p-0">
                        <table class="table table-striped table-hover mb-0">
                            <thead class="table-dark">
                                <tr>
                                    <th>ID</th>
                                    <th>Temperature (°C)</th>
                                    <th>Status</th>
                                    <th>Timestamp</th>
                                </tr>
                            </thead>
                            <tbody>
                            <?php
                            $logs = $db->query("SELECT * FROM temperature_logs ORDER BY timestamp DESC LIMIT 10");
                            while ($row = $logs->fetch_assoc()):
                                $statusClass = 'status-' . strtolower($row['status']);
                            ?>
                                <tr>
                                    <td><?= $row['id'] ?></td>
                                    <td><?= $row['temperature'] ?></td>
                                    <td class="<?= $statusClass ?>">
                                        <i class="bi 
                                            <?= $row['status'] === 'CRITICAL' ? 'bi-chevron-double-up' : 
                                               ($row['status'] === 'WARNING' ? 'bi-chevron-double-down' : 'bi-check-circle') ?> 
                                            me-1"></i>
                                        <?= $row['status'] ?>
                                    </td>
                                    <td><?= $row['timestamp'] ?></td>
                                </tr>
                            <?php endwhile; ?>
                            </tbody>
                        </table>
                    </div>
                </div>
            </div>
            
            <!-- Alerts Tab -->
            <div class="tab-pane fade" id="alerts" role="tabpanel">
                <div class="card">
                    <div class="card-header bg-danger text-white">
                        <h5 class="card-title mb-0">
                            <i class="bi bi-exclamation-triangle-fill me-1"></i>Security Alerts
                        </h5>
                    </div>
                    <div class="card-body table-responsive p-0">
                        <table class="table table-striped table-hover mb-0">
                            <thead class="table-dark">
                                <tr>
                                    <th>ID</th>
                                    <th>Type</th>
                                    <th>Message</th>
                                    <th>Severity</th>
                                    <th>Timestamp</th>
                                </tr>
                            </thead>
                            <tbody>
                            <?php
                            $alerts = $db->query("SELECT * FROM security_alerts ORDER BY timestamp DESC LIMIT 15");
                            while ($alert = $alerts->fetch_assoc()):
                                $severityClass = 'severity-' . strtolower($alert['severity']);
                                $iconClass = [
                                    'high' => 'bi-exclamation-octagon-fill text-danger',
                                    'medium' => 'bi-exclamation-triangle-fill text-warning',
                                    'low' => 'bi-info-circle-fill text-secondary'
                                ][strtolower($alert['severity'])] ?? 'bi-info-circle-fill';
                            ?>
                                <tr>
                                    <td><?= $alert['id'] ?></td>
                                    <td><?= htmlspecialchars($alert['alert_type']) ?></td>
                                    <td><?= htmlspecialchars($alert['message']) ?></td>
                                    <td class="<?= $severityClass ?>">
                                        <i class="bi <?= $iconClass ?> me-1"></i>
                                        <?= ucfirst($alert['severity']) ?>
                                    </td>
                                    <td><?= $alert['timestamp'] ?></td>
                                </tr>
                            <?php endwhile; ?>
                            </tbody>
                        </table>
                    </div>
                </div>
            </div>
            
            <!-- Banned IPs Tab -->
            <div class="tab-pane fade" id="bans" role="tabpanel">
                <div class="card">
                    <div class="card-header bg-warning text-dark">
                        <h5 class="card-title mb-0">
                            <i class="bi bi-ban me-1"></i>Banned IP Addresses
                        </h5>
                    </div>
                    <div class="card-body table-responsive p-0">
                        <table class="table table-striped table-hover mb-0">
                            <thead class="table-dark">
                                <tr>
                                    <th>IP Address</th>
                                    <th>Banned At</th>
                                    <th>Duration</th>
                                    <th>Reason</th>
                                    <th>Attempts</th>
                                    <th>Action</th>
                                </tr>
                            </thead>
                            <tbody>
                            <?php
                            $bans = $db->query("SELECT * FROM banned_ips ORDER BY banned_at DESC");
                            while ($ban = $bans->fetch_assoc()):
                                $isPermanent = $ban['is_permanent'] ?? false;
                                $banTime = strtotime($ban['banned_at']);
                                $currentTime = time();
                                $timeLeft = $banTime + (30 * 60) - $currentTime;
                                $duration = $isPermanent ? 'Permanent' : 
                                    ($timeLeft > 0 ? gmdate("H:i:s", $timeLeft) : 'Expired');
                            ?>
                                <tr>
                                    <td><?= htmlspecialchars($ban['ip_address']) ?></td>
                                    <td><?= $ban['banned_at'] ?></td>
                                    <td class="<?= $isPermanent ? 'permanent-ban' : '' ?>">
                                        <?= $duration ?>
                                    </td>
                                    <td>
                                        <?= htmlspecialchars($ban['reason'] ?? 'Multiple failed attempts') ?>
                                        <?php if ($ban['banned_by']): ?>
                                            <div class="ban-reason">by <?= htmlspecialchars($ban['banned_by']) ?></div>
                                        <?php endif; ?>
                                    </td>
                                    <td><?= $ban['attempts'] ?></td>
                                    <td>
                                        <?php if (!$isPermanent || $_SESSION['username'] === 'admin'): ?>
                                            <a href="?unban_ip=<?= urlencode($ban['ip_address']) ?>" 
                                               class="btn btn-sm btn-success"
                                               onclick="return confirm('Are you sure you want to unban this IP?')">
                                                <i class="bi bi-unlock"></i> Unban
                                            </a>
                                        <?php else: ?>
                                            <span class="text-muted">Permanent</span>
                                        <?php endif; ?>
                                    </td>
                                </tr>
                            <?php endwhile; ?>
                            <?php if ($bans->num_rows === 0): ?>
                                <tr>
                                    <td colspan="6" class="text-center py-4">No banned IP addresses found</td>
                                </tr>
                            <?php endif; ?>
                            </tbody>
                        </table>
                    </div>
                </div>
            </div>
        </div>
    </div>
    
    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js"></script>
    <script>
        // Function to send manual temperature reading
        function sendManualReading() {
            const temp = parseFloat(prompt("Enter temperature value:"));
            if (!isNaN(temp)) {
                fetch('?manual_reading=1&temp=' + temp)
                    .then(response => {
                        if (!response.ok) {
                            throw new Error('Network response was not ok');
                        }
                        return response.json();
                    })
                    .then(data => {
                        if (data.success) {
                            alert("Temperature reading sent successfully");
                            updateTemperature(); // Refresh display
                        } else {
                            alert("Error: " + (data.message || "Failed to send reading"));
                        }
                    })
                    .catch(err => {
                        console.error('Error sending manual reading:', err);
                        alert("Failed to send reading. Check console for details.");
                    });
            }
        }
        
        function updateTemperature() {
            fetch('?live_temp=1')
                .then(res => {
                    if (!res.ok) {
                        throw new Error('Network response was not ok');
                    }
                    return res.json();
                })
                .then(data => {
                    const tempElement = document.getElementById('live-temp');
                    const statusElement = document.getElementById('temp-status');
                    const lastUpdatedElement = document.getElementById('last-updated');
                    
                    if (data.temperature !== null) {
                        tempElement.textContent = data.temperature.toFixed(1);
                        
                        // Update status with proper classes
                        statusElement.textContent = data.status;
                        
                        // Clear all status classes first
                        statusElement.className = 'badge';
                        
                        // Add appropriate class based on status
                        if (data.status === 'CRITICAL') {
                            statusElement.classList.add('bg-danger', 'status-danger');
                        } else if (data.status === 'WARNING') {
                            statusElement.classList.add('bg-warning', 'status-warning');
                        } else {
                            statusElement.classList.add('bg-success', 'status-normal');
                        }
                        
                        // Update timestamp
                        const now = new Date();
                        lastUpdatedElement.textContent = now.toLocaleTimeString();
                    }
                })
                .catch(err => {
                    console.error('Error fetching temperature:', err);
                    // You might want to update the UI to show an error state here
                });
        }
        
        // Update immediately and then every 3 seconds
        updateTemperature();
        setInterval(updateTemperature, 3000);
        
        // Highlight active tab on page load
        document.addEventListener('DOMContentLoaded', function() {
            const urlParams = new URLSearchParams(window.location.search);
            if (urlParams.get('tab') === 'alerts') {
                const alertTab = new bootstrap.Tab(document.getElementById('alerts-tab'));
                alertTab.show();
            } else if (urlParams.get('tab') === 'bans') {
                const bansTab = new bootstrap.Tab(document.getElementById('bans-tab'));
                bansTab.show();
            }
        });
    </script>
<?php endif; ?>
</body>
</html>
