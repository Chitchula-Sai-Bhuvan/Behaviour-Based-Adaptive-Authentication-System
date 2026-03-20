# API Usage Examples

Complete examples for integrating with the Behaviour-Based Adaptive Authentication System.

## Authentication Flow

### 1. Register a New User

```bash
curl -X POST http://localhost:8000/api/register \
  -H "Content-Type: application/json" \
  -d '{
    "username": "alice@example.com",
    "password": "SecurePass123!"
  }'
```

**Response (201 Created):**
```json
{
  "user_id": 1,
  "username": "alice@example.com",
  "message": "User registered successfully"
}
```

**Error (409 Conflict):**
```json
{
  "detail": "Username 'alice@example.com' is already registered."
}
```

**Error (422 Unprocessable Entity):**
```json
{
  "detail": "Password policy: Password must contain at least one uppercase letter."
}
```

### 2. Login

```bash
curl -X POST http://localhost:8000/api/login \
  -H "Content-Type: application/json" \
  -d '{
    "username": "alice@example.com",
    "password": "SecurePass123!"
  }'
```

**Response (200 OK):**
```json
{
  "user_id": 1,
  "username": "alice@example.com",
  "session_id": "550e8400-e29b-41d4-a716-446655440000",
  "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "refresh_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "token_type": "bearer",
  "expires_in": 1800
}
```

**Error on Account Lockout (401 Unauthorized):**
```json
{
  "detail": "Account is temporarily locked. Try again later."
}
```

### 3. Request MFA Challenge

```bash
curl -X POST http://localhost:8000/api/mfa/request \
  -H "Content-Type: application/json" \
  -d '{
    "user_id": 1,
    "session_id": "550e8400-e29b-41d4-a716-446655440000"
  }'
```

**Response (200 OK):**
```json
{
  "challenge_id": "mfa_550e8400-e29b-41d4-a716-446655440000",
  "created_at": "2026-03-20T10:30:00Z",
  "expires_at": "2026-03-20T10:35:00Z",
  "message": "MFA challenge created. Check your registered device."
}
```

### 4. Respond to MFA Challenge

```bash
curl -X POST http://localhost:8000/api/mfa/respond \
  -H "Content-Type: application/json" \
  -d '{
    "user_id": 1,
    "challenge_id": "mfa_550e8400-e29b-41d4-a716-446655440000",
    "approved": true
  }'
```

**Response (200 OK - Normal):**
```json
{
  "user_id": 1,
  "approved": true,
  "risk_score": 15,
  "decision": "ALLOW",
  "triggered_signals": ["ip_change_detected"],
  "message": "MFA approved. Access granted.",
  "session_id": "550e8400-e29b-41d4-a716-446655440000"
}
```

**Response (200 OK - Requires Verification):**
```json
{
  "user_id": 1,
  "approved": true,
  "risk_score": 50,
  "decision": "VERIFY",
  "triggered_signals": [
    "excess_mfa_requests",
    "repeated_approvals",
    "new_device_detected"
  ],
  "message": "Unusual activity detected. Additional verification required.",
  "session_id": "550e8400-e29b-41d4-a716-446655440000"
}
```

**Response (200 OK - Access Denied):**
```json
{
  "user_id": 1,
  "approved": true,
  "risk_score": 95,
  "decision": "BLOCK",
  "triggered_signals": [
    "excess_mfa_requests",
    "repeated_approvals",
    "impossible_travel",
    "new_device_detected"
  ],
  "message": "Access denied due to high-risk behaviour.",
  "session_id": "550e8400-e29b-41d4-a716-446655440000"
}
```

## Token Refresh Flow

### 5. Refresh Access Token

```bash
curl -X POST http://localhost:8000/api/refresh \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer <refresh_token>" \
  -d '{}'
```

**Response (200 OK):**
```json
{
  "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "refresh_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "token_type": "bearer",
  "expires_in": 1800
}
```

### 6. Logout

```bash
curl -X POST http://localhost:8000/api/logout \
  -H "Authorization: Bearer <access_token>"
```

**Response (200 OK):**
```json
{
  "message": "Logged out successfully.",
  "session_id": "550e8400-e29b-41d4-a716-446655440000"
}
```

## Risk Evaluation API

### 7. Evaluate User Risk In Real-Time

```bash
curl -X GET "http://localhost:8000/api/risk/evaluate?user_id=1" \
  -H "Authorization: Bearer <access_token>"
```

**Response (200 OK):**
```json
{
  "user_id": 1,
  "risk_score": 35,
  "decision": "ALLOW",
  "triggered_signals": [
    {
      "signal_name": "ip_change_detected",
      "weight": 15,
      "description": "User logged in from different IP subnet"
    }
  ],
  "signal_details": {
    "excess_mfa_requests": false,
    "rapid_login_attempts": false,
    "repeated_approvals": false,
    "new_device_detected": false,
    "ip_change_detected": true,
    "impossible_travel": false,
    "off_hours_access": false
  },
  "evaluated_at": "2026-03-20T10:45:30Z"
}
```

### 8. Verify Audit Chain Integrity

```bash
curl -X GET "http://localhost:8000/api/risk/audit?user_id=1" \
  -H "Authorization: Bearer <access_token>"
```

**Response (200 OK - No Tampering):**
```json
{
  "user_id": 1,
  "valid": true,
  "events_checked": 42,
  "integrity_timestamp": "2026-03-20T10:46:00Z",
  "message": "Audit chain integrity verified. No tampering detected."
}
```

**Response (200 OK - Tampering Detected):**
```json
{
  "user_id": 1,
  "valid": false,
  "events_checked": 42,
  "broken_at_event_id": 35,
  "broken_at_timestamp": "2026-03-20T10:40:00Z",
  "message": "Tampering detected! Chain verification failed at event #35.",
  "integrity_timestamp": "2026-03-20T10:46:00Z"
}
```

## Logging & Audit API

### 9. Get Authentication Events

```bash
curl -X GET "http://localhost:8000/api/logs/events?user_id=1" \
  -H "Authorization: Bearer <access_token>"
```

**Response (200 OK):**
```json
{
  "user_id": 1,
  "events": [
    {
      "event_id": 100,
      "event_type": "LOGIN",
      "timestamp": "2026-03-20T10:30:00Z",
      "ip_address": "192.168.1.5",
      "device_fingerprint": "abc123xyz789",
      "success": true,
      "session_id": "550e8400-e29b-41d4-a716-446655440000"
    },
    {
      "event_id": 101,
      "event_type": "MFA_REQUEST",
      "timestamp": "2026-03-20T10:31:00Z",
      "ip_address": "192.168.1.5",
      "device_fingerprint": "abc123xyz789",
      "success": true,
      "session_id": "550e8400-e29b-41d4-a716-446655440000"
    }
  ],
  "total": 2
}
```

### 10. Get Risk Decisions History

```bash
curl -X GET "http://localhost:8000/api/logs/decisions?user_id=1" \
  -H "Authorization: Bearer <access_token>"
```

**Response (200 OK):**
```json
{
  "user_id": 1,
  "decisions": [
    {
      "decision_id": 50,
      "risk_score": 15,
      "decision": "ALLOW",
      "triggered_signals": ["ip_change_detected"],
      "reason": "Low risk - single signal triggered",
      "timestamp": "2026-03-20T10:31:30Z"
    },
    {
      "decision_id": 51,
      "risk_score": 50,
      "decision": "VERIFY",
      "triggered_signals": ["excess_mfa_requests", "repeated_approvals"],
      "reason": "MFA fatigue attack characteristics detected",
      "timestamp": "2026-03-20T10:35:00Z"
    }
  ],
  "total": 2
}
```

### 11. Get Trusted Devices

```bash
curl -X GET "http://localhost:8000/api/logs/devices?user_id=1" \
  -H "Authorization: Bearer <access_token>"
```

**Response (200 OK):**
```json
{
  "user_id": 1,
  "devices": [
    {
      "device_id": "abc123xyz789",
      "device_label": "Home Laptop",
      "first_seen_at": "2026-03-15T14:20:00Z",
      "last_seen_at": "2026-03-20T10:30:00Z",
      "is_active": true,
      "login_count": 28
    },
    {
      "device_id": "def456uvw789",
      "device_label": "Mobile Phone",
      "first_seen_at": "2026-03-18T09:15:00Z",
      "last_seen_at": "2026-03-20T08:45:00Z",
      "is_active": true,
      "login_count": 5
    }
  ],
  "total": 2
}
```

### 12. Get Active Sessions

```bash
curl -X GET "http://localhost:8000/api/logs/sessions?user_id=1" \
  -H "Authorization: Bearer <access_token>"
```

**Response (200 OK):**
```json
{
  "user_id": 1,
  "sessions": [
    {
      "session_id": "550e8400-e29b-41d4-a716-446655440000",
      "ip_address": "192.168.1.5",
      "created_at": "2026-03-20T10:30:00Z",
      "last_active_at": "2026-03-20T10:46:00Z",
      "expires_at": "2026-03-21T10:30:00Z",
      "is_active": true,
      "terminated_reason": null
    }
  ],
  "total": 1
}
```

## Browser-Based Integration

### HTML Form Example

```html
<!DOCTYPE html>
<html>
<head>
    <title>Login</title>
    <link rel="stylesheet" href="https://cdn.tailwindcss.com">
</head>
<body class="bg-gray-100">
    <div class="flex items-center justify-center min-h-screen">
        <div class="bg-white p-8 rounded-lg shadow-md w-96">
            <h1 class="text-2xl font-bold mb-6">Login</h1>
            
            <form id="loginForm">
                <div class="mb-4">
                    <label class="block text-sm font-medium mb-2">Username</label>
                    <input type="text" id="username" required 
                           class="w-full px-4 py-2 border rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500">
                </div>
                
                <div class="mb-6">
                    <label class="block text-sm font-medium mb-2">Password</label>
                    <input type="password" id="password" required 
                           class="w-full px-4 py-2 border rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500">
                </div>
                
                <button type="submit" class="w-full bg-blue-600 text-white py-2 rounded-lg hover:bg-blue-700">
                    Login
                </button>
            </form>
            
            <div id="errorMessage" class="mt-4 p-3 bg-red-100 text-red-700 rounded-lg hidden"></div>
            <div id="successMessage" class="mt-4 p-3 bg-green-100 text-green-700 rounded-lg hidden"></div>
        </div>
    </div>

    <script>
        document.getElementById('loginForm').addEventListener('submit', async (e) => {
            e.preventDefault();
            
            const username = document.getElementById('username').value;
            const password = document.getElementById('password').value;
            
            try {
                const response = await fetch('/api/login', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ username, password })
                });
                
                if (response.ok) {
                    const data = await response.json();
                    localStorage.setItem('access_token', data.access_token);
                    localStorage.setItem('refresh_token', data.refresh_token);
                    window.location.href = '/dashboard';
                } else {
                    const error = await response.json();
                    showError(error.detail);
                }
            } catch (err) {
                showError('Network error. Please try again.');
            }
        });
        
        function showError(message) {
            const errorDiv = document.getElementById('errorMessage');
            errorDiv.textContent = message;
            errorDiv.classList.remove('hidden');
        }
    </script>
</body>
</html>
```

### JavaScript API Client

```javascript
// auth-client.js
class AuthClient {
    constructor(baseURL = 'http://localhost:8000') {
        this.baseURL = baseURL;
        this.accessToken = localStorage.getItem('access_token');
    }
    
    async register(username, password) {
        const response = await fetch(`${this.baseURL}/api/register`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ username, password })
        });
        return response.json();
    }
    
    async login(username, password) {
        const response = await fetch(`${this.baseURL}/api/login`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ username, password })
        });
        const data = await response.json();
        if (response.ok) {
            this.accessToken = data.access_token;
            localStorage.setItem('access_token', data.access_token);
            localStorage.setItem('refresh_token', data.refresh_token);
        }
        return data;
    }
    
    async requestMFA(userId, sessionId) {
        return this.apiCall(`/api/mfa/request?user_id=${userId}&session_id=${sessionId}`, 'POST', {});
    }
    
    async respondMFA(userId, challengeId, approved) {
        return this.apiCall('/api/mfa/respond', 'POST', {
            user_id: userId,
            challenge_id: challengeId,
            approved
        });
    }
    
    async getRiskScore(userId) {
        return this.apiCall(`/api/risk/evaluate?user_id=${userId}`, 'GET');
    }
    
    async getEvents(userId) {
        return this.apiCall(`/api/logs/events?user_id=${userId}`, 'GET');
    }
    
    async logout() {
        await this.apiCall('/api/logout', 'POST', {});
        localStorage.removeItem('access_token');
        localStorage.removeItem('refresh_token');
        this.accessToken = null;
    }
    
    async apiCall(endpoint, method = 'GET', body = null) {
        const options = {
            method,
            headers: {
                'Content-Type': 'application/json',
                'Authorization': `Bearer ${this.accessToken}`
            }
        };
        
        if (body) {
            options.body = JSON.stringify(body);
        }
        
        const response = await fetch(`${this.baseURL}${endpoint}`, options);
        return response.json();
    }
}

// Usage
const client = new AuthClient();
const result = await client.login('alice@example.com', 'SecurePass123!');
console.log('Login successful:', result);
```

## Python Client Example

```python
# auth_client.py
import requests
from typing import Optional, Dict, Any

class AuthClient:
    def __init__(self, base_url: str = "http://localhost:8000"):
        self.base_url = base_url
        self.session = requests.Session()
        self.access_token = None
        self.refresh_token = None
    
    def register(self, username: str, password: str) -> Dict[str, Any]:
        response = self.session.post(
            f"{self.base_url}/api/register",
            json={"username": username, "password": password}
        )
        return response.json()
    
    def login(self, username: str, password: str) -> Dict[str, Any]:
        response = self.session.post(
            f"{self.base_url}/api/login",
            json={"username": username, "password": password}
        )
        data = response.json()
        if response.status_code == 200:
            self.access_token = data["access_token"]
            self.refresh_token = data["refresh_token"]
        return data
    
    def request_mfa(self, user_id: int, session_id: str) -> Dict[str, Any]:
        return self._api_call(
            f"/api/mfa/request?user_id={user_id}&session_id={session_id}",
            "POST",
            {}
        )
    
    def respond_mfa(self, user_id: int, challenge_id: str, approved: bool) -> Dict[str, Any]:
        return self._api_call(
            "/api/mfa/respond",
            "POST",
            {
                "user_id": user_id,
                "challenge_id": challenge_id,
                "approved": approved
            }
        )
    
    def evaluate_risk(self, user_id: int) -> Dict[str, Any]:
        return self._api_call(f"/api/risk/evaluate?user_id={user_id}", "GET")
    
    def logout(self) -> Dict[str, Any]:
        result = self._api_call("/api/logout", "POST", {})
        self.access_token = None
        self.refresh_token = None
        return result
    
    def _api_call(self, endpoint: str, method: str = "GET", body: Optional[Dict] = None) -> Dict[str, Any]:
        headers = {
            "Authorization": f"Bearer {self.access_token}"
        }
        
        url = f"{self.base_url}{endpoint}"
        
        if method == "GET":
            response = self.session.get(url, headers=headers)
        elif method == "POST":
            response = self.session.post(url, json=body, headers=headers)
        else:
            raise ValueError(f"Unsupported method: {method}")
        
        return response.json()

# Usage
if __name__ == "__main__":
    client = AuthClient()
    result = client.login("alice@example.com", "SecurePass123!")
    print("Login successful:", result)
    
    risk = client.evaluate_risk(user_id=result["user_id"])
    print("Risk evaluation:", risk)
```

---

**More Examples**: See [test_edge_cases.py](tests/test_edge_cases.py) and [simulate_attacks.py](tests/simulate_attacks.py) for additional examples.
