<?php
header("Content-Type: application/json");
header("Access-Control-Allow-Origin: *");
header("Access-Control-Allow-Methods: GET, POST, PUT, OPTIONS");
header("Access-Control-Allow-Headers: Content-Type");
header("Access-Control-Max-Age: 3600");

// Database configuration
$servername = "localhost";
$username = "root";
$password = "";
$dbname = "ecobin";

// Create connection
$conn = new mysqli($servername, $username, $password, $dbname);

// Check connection
if ($conn->connect_error) {
    die(json_encode(["success" => false, "message" => "Connection failed: " . $conn->connect_error]));
}

// Initialize database tables if they don't exist
function initializeDatabase($conn) {
    $tables = [
        "CREATE TABLE IF NOT EXISTS users (
            id INT AUTO_INCREMENT PRIMARY KEY,
            name VARCHAR(100) NOT NULL,
            email VARCHAR(100) NOT NULL UNIQUE,
            password VARCHAR(255) NOT NULL,
            address TEXT NOT NULL,
            phone VARCHAR(15) NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
        )",
        
        "CREATE TABLE IF NOT EXISTS collectors (
            id INT AUTO_INCREMENT PRIMARY KEY,
            name VARCHAR(100) NOT NULL,
            email VARCHAR(100) NOT NULL UNIQUE,
            password VARCHAR(255) NOT NULL,
            phone VARCHAR(15) NOT NULL,
            area VARCHAR(100) NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
        )",
        
        "CREATE TABLE IF NOT EXISTS waste_entries (
            id INT AUTO_INCREMENT PRIMARY KEY,
            user_id INT NOT NULL,
            type VARCHAR(50) NOT NULL,
            amount DECIMAL(10,2) NOT NULL,
            method VARCHAR(50) NOT NULL,
            date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
        )",
        
        "CREATE TABLE IF NOT EXISTS collection_requests (
            id INT AUTO_INCREMENT PRIMARY KEY,
            user_id INT NOT NULL,
            collector_id INT,
            waste_type VARCHAR(50) NOT NULL,
            address TEXT NOT NULL,
            status ENUM('Pending', 'Approved', 'Rejected', 'Completed') DEFAULT 'Pending',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
            FOREIGN KEY (collector_id) REFERENCES collectors(id) ON DELETE SET NULL
        )",
        
        "CREATE TABLE IF NOT EXISTS user_notifications (
            id INT AUTO_INCREMENT PRIMARY KEY,
            user_id INT NOT NULL,
            request_id INT,
            message TEXT NOT NULL,
            is_read BOOLEAN DEFAULT FALSE,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
            FOREIGN KEY (request_id) REFERENCES collection_requests(id) ON DELETE SET NULL
        )",
        
        "CREATE TABLE IF NOT EXISTS feedback (
            id INT AUTO_INCREMENT PRIMARY KEY,
            name VARCHAR(100) NOT NULL,
            email VARCHAR(100) NOT NULL,
            subject VARCHAR(100) NOT NULL,
            message TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )",
        
        // Add default collector account
        "INSERT IGNORE INTO collectors (name, email, password, phone, area) 
         VALUES ('Dhule Waste Collector', 'collector@ecobin.com', 'collector123', '9876543210', 'Dhule City')"
    ];

    foreach ($tables as $sql) {
        if (!$conn->query($sql)) {
            die(json_encode(["success" => false, "message" => "Error creating table: " . $conn->error]));
        }
    }
}

// Initialize database
initializeDatabase($conn);

// Get the request method and URI
$method = $_SERVER['REQUEST_METHOD'];
$request = isset($_SERVER['PATH_INFO']) ? $_SERVER['PATH_INFO'] : '';

// Helper function to send JSON response
function sendResponse($success, $message = "", $data = []) {
    echo json_encode([
        "success" => $success,
        "message" => $message,
        "data" => $data
    ]);
    exit;
}

// Handle different API endpoints
if ($method === 'POST' && strpos($request, '/register') !== false) {
    $data = json_decode(file_get_contents('php://input'), true);
    
    // Validate input
    if (empty($data['name']) || empty($data['email']) || empty($data['password']) || 
        empty($data['address']) || empty($data['phone'])) {
        sendResponse(false, "All fields are required");
    }

    // Validate email
    if (!filter_var($data['email'], FILTER_VALIDATE_EMAIL)) {
        sendResponse(false, "Invalid email format");
    }

    // Validate phone (10 digits)
    if (!preg_match('/^[0-9]{10}$/', $data['phone'])) {
        sendResponse(false, "Phone number must be 10 digits");
    }

    // Check if email already exists
    $stmt = $conn->prepare("SELECT id FROM users WHERE email = ?");
    $stmt->bind_param("s", $data['email']);
    $stmt->execute();
    $result = $stmt->get_result();
    
    if ($result->num_rows > 0) {
        sendResponse(false, "Email already registered");
    }
    $stmt->close();

    // Hash password
    $hashedPassword = password_hash($data['password'], PASSWORD_DEFAULT);

    // Insert new user
    $stmt = $conn->prepare("INSERT INTO users (name, email, password, address, phone) VALUES (?, ?, ?, ?, ?)");
    $stmt->bind_param("sssss", $data['name'], $data['email'], $hashedPassword, $data['address'], $data['phone']);

    if ($stmt->execute()) {
        $userId = $stmt->insert_id;
        
        // Get the newly created user
        $stmt = $conn->prepare("SELECT id, name, email, address, phone FROM users WHERE id = ?");
        $stmt->bind_param("i", $userId);
        $stmt->execute();
        $result = $stmt->get_result();
        $user = $result->fetch_assoc();
        
        sendResponse(true, "Registration successful", ["user" => $user]);
    } else {
        sendResponse(false, "Registration failed: " . $stmt->error);
    }
    $stmt->close();
}
elseif ($method === 'POST' && strpos($request, '/login') !== false) {
    $data = json_decode(file_get_contents('php://input'), true);
    
    // Validate input
    if (empty($data['email']) || empty($data['password'])) {
        sendResponse(false, "Email and password are required");
    }

    // Get user from database
    $stmt = $conn->prepare("SELECT id, name, email, password, address, phone FROM users WHERE email = ?");
    $stmt->bind_param("s", $data['email']);
    $stmt->execute();
    $result = $stmt->get_result();
    
    if ($result->num_rows === 0) {
        sendResponse(false, "Invalid email or password");
    }

    $user = $result->fetch_assoc();
    $stmt->close();

    // Verify password
    if (!password_verify($data['password'], $user['password'])) {
        sendResponse(false, "Invalid email or password");
    }

    // Remove password before sending back
    unset($user['password']);
    sendResponse(true, "Login successful", ["user" => $user]);
}
elseif ($method === 'POST' && strpos($request, '/collector-login') !== false) {
    $data = json_decode(file_get_contents('php://input'), true);
    
    // Validate input
    if (empty($data['email']) || empty($data['password'])) {
        sendResponse(false, "Email and password are required");
    }

    // Get collector from database
    $stmt = $conn->prepare("SELECT id, name, email, phone, area FROM collectors WHERE email = ? AND password = ?");
    $stmt->bind_param("ss", $data['email'], $data['password']);
    $stmt->execute();
    $result = $stmt->get_result();
    
    if ($result->num_rows === 0) {
        sendResponse(false, "Invalid email or password");
    }

    $collector = $result->fetch_assoc();
    $stmt->close();

    sendResponse(true, "Login successful", ["collector" => $collector]);
}
elseif ($method === 'POST' && strpos($request, '/collection') !== false) {
    $data = json_decode(file_get_contents('php://input'), true);
    
    // Validate input
    if (empty($data['userId']) || empty($data['wasteType']) || empty($data['address'])) {
        sendResponse(false, "All fields are required");
    }

    // Insert collection request
    $stmt = $conn->prepare("INSERT INTO collection_requests (user_id, waste_type, address, status) VALUES (?, ?, ?, 'Pending')");
    $stmt->bind_param("sss", $data['userId'], $data['wasteType'], $data['address']);

    if ($stmt->execute()) {
        $requestId = $stmt->insert_id;
        
        // Create notification for collectors
        $notificationMsg = "New collection request #$requestId for {$data['wasteType']}";
        $stmt2 = $conn->prepare("INSERT INTO user_notifications (user_id, request_id, message) VALUES (?, ?, ?)");
        $stmt2->bind_param("iis", $data['userId'], $requestId, $notificationMsg);
        $stmt2->execute();
        $stmt2->close();
        
        sendResponse(true, "Collection request submitted", ["requestId" => $requestId]);
    } else {
        sendResponse(false, "Failed to submit collection request: " . $stmt->error);
    }
    $stmt->close();
}
elseif ($method === 'POST' && strpos($request, '/collection-action') !== false) {
    $data = json_decode(file_get_contents('php://input'), true);
    
    // Validate input
    if (empty($data['requestId']) || empty($data['action']) || empty($data['collectorId'])) {
        sendResponse(false, "Invalid request parameters");
    }

    // Get current status
    $stmt = $conn->prepare("SELECT status, user_id FROM collection_requests WHERE id = ?");
    $stmt->bind_param("i", $data['requestId']);
    $stmt->execute();
    $result = $stmt->get_result();
    
    if ($result->num_rows === 0) {
        sendResponse(false, "Request not found");
    }
    
    $request = $result->fetch_assoc();
    $currentStatus = $request['status'];
    $userId = $request['user_id'];
    $stmt->close();

    // Validate action
    $validActions = ['approve', 'reject', 'complete'];
    if (!in_array($data['action'], $validActions)) {
        sendResponse(false, "Invalid action");
    }

    // Check status transitions
    if ($data['action'] === 'approve' && $currentStatus !== 'Pending') {
        sendResponse(false, "Only pending requests can be approved");
    }
    
    if ($data['action'] === 'reject' && $currentStatus !== 'Pending') {
        sendResponse(false, "Only pending requests can be rejected");
    }
    
    if ($data['action'] === 'complete' && $currentStatus !== 'Approved') {
        sendResponse(false, "Only approved requests can be completed");
    }

    // Update request status
    $newStatus = '';
    switch($data['action']) {
        case 'approve':
            $newStatus = 'Approved';
            break;
        case 'reject':
            $newStatus = 'Rejected';
            break;
        case 'complete':
            $newStatus = 'Completed';
            break;
    }

    $stmt = $conn->prepare("UPDATE collection_requests SET status = ?, collector_id = ?, updated_at = NOW() WHERE id = ?");
    $stmt->bind_param("sii", $newStatus, $data['collectorId'], $data['requestId']);

    if ($stmt->execute()) {
        // Create notification for user
        $notificationMsg = "Your collection request #{$data['requestId']} has been {$newStatus}";
        $stmt2 = $conn->prepare("INSERT INTO user_notifications (user_id, request_id, message) VALUES (?, ?, ?)");
        $stmt2->bind_param("iis", $userId, $data['requestId'], $notificationMsg);
        $stmt2->execute();
        $stmt2->close();
        
        sendResponse(true, "Request updated successfully", ["status" => $newStatus]);
    } else {
        sendResponse(false, "Failed to update request: " . $stmt->error);
    }
    $stmt->close();
}
elseif ($method === 'GET' && strpos($request, '/collection-requests') !== false) {
    // Get query parameters
    $params = [];
    parse_str($_SERVER['QUERY_STRING'], $params);
    
    $status = isset($params['status']) ? $params['status'] : null;
    $collectorId = isset($params['collectorId']) ? $params['collectorId'] : null;
    $userId = isset($params['userId']) ? $params['userId'] : null;
    
    // Build query based on parameters
    $query = "SELECT cr.*, u.name as user_name, u.phone as user_phone 
              FROM collection_requests cr
              JOIN users u ON cr.user_id = u.id";
    
    $conditions = [];
    $types = "";
    $values = [];
    
    if ($status) {
        $conditions[] = "cr.status = ?";
        $types .= "s";
        $values[] = $status;
    }
    
    if ($collectorId) {
        $conditions[] = "cr.collector_id = ?";
        $types .= "i";
        $values[] = $collectorId;
    }
    
    if ($userId) {
        $conditions[] = "cr.user_id = ?";
        $types .= "i";
        $values[] = $userId;
    }
    
    if (count($conditions)) {
        $query .= " WHERE " . implode(" AND ", $conditions);
    }
    
    $query .= " ORDER BY cr.created_at DESC";
    
    $stmt = $conn->prepare($query);
    
    if (count($values)) {
        $stmt->bind_param($types, ...$values);
    }
    
    $stmt->execute();
    $result = $stmt->get_result();
    $requests = [];
    
    while ($row = $result->fetch_assoc()) {
        $requests[] = $row;
    }
    
    $stmt->close();
    sendResponse(true, "Requests retrieved", ["requests" => $requests]);
}
elseif ($method === 'GET' && strpos($request, '/collector-info') !== false) {
    // Get query parameters
    $params = [];
    parse_str($_SERVER['QUERY_STRING'], $params);
    
    if (empty($params['collectorId'])) {
        sendResponse(false, "Collector ID is required");
    }

    // Get collector info
    $stmt = $conn->prepare("SELECT id, name, email, phone, area FROM collectors WHERE id = ?");
    $stmt->bind_param("i", $params['collectorId']);
    $stmt->execute();
    $result = $stmt->get_result();
    
    if ($result->num_rows === 0) {
        sendResponse(false, "Collector not found");
    }

    $collector = $result->fetch_assoc();
    $stmt->close();

    sendResponse(true, "Collector info retrieved", ["collector" => $collector]);
}
elseif ($method === 'GET' && strpos($request, '/user-notifications') !== false) {
    // Get query parameters
    $params = [];
    parse_str($_SERVER['QUERY_STRING'], $params);
    
    if (empty($params['userId'])) {
        sendResponse(false, "User ID is required");
    }

    // Get user notifications
    $stmt = $conn->prepare("SELECT * FROM user_notifications WHERE user_id = ? ORDER BY created_at DESC");
    $stmt->bind_param("i", $params['userId']);
    $stmt->execute();
    $result = $stmt->get_result();
    
    $notifications = [];
    while ($row = $result->fetch_assoc()) {
        $notifications[] = $row;
    }
    
    $stmt->close();
    sendResponse(true, "Notifications retrieved", ["notifications" => $notifications]);
}
elseif ($method === 'POST' && strpos($request, '/feedback') !== false) {
    $data = json_decode(file_get_contents('php://input'), true);
    
    // Validate input
    if (empty($data['name']) || empty($data['email']) || empty($data['subject']) || empty($data['message'])) {
        sendResponse(false, "All fields are required");
    }

    // Validate email
    if (!filter_var($data['email'], FILTER_VALIDATE_EMAIL)) {
        sendResponse(false, "Invalid email format");
    }

    // Insert feedback
    $stmt = $conn->prepare("INSERT INTO feedback (name, email, subject, message) VALUES (?, ?, ?, ?)");
    $stmt->bind_param("ssss", $data['name'], $data['email'], $data['subject'], $data['message']);

    if ($stmt->execute()) {
        sendResponse(true, "Feedback submitted successfully");
    } else {
        sendResponse(false, "Failed to submit feedback: " . $stmt->error);
    }
    $stmt->close();
}
else {
    sendResponse(false, "Endpoint not found");
}

$conn->close();
?>