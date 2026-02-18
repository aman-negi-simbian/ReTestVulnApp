# XSS Vulnerability Demonstration App

An educational application demonstrating three different states of XSS (Cross-Site Scripting) vulnerability.

## State Encoding

States are encoded as numbers for brevity:

- **0** = FIX_COMPLETELY (Fully Fixed - Complete Sanitization with DOMPurify)
- **1** = FIX_PARTIALLY (Partially Fixed - Script Tags Allowed)
- **2** = MAKE_VULNERABLE (Not Fixed - Fully Vulnerable to XSS)

## Quick Start

### Local
```bash
npm install
npm start
# Open http://localhost:3000
```

### Docker
```bash
docker-compose up
# Open http://localhost:3000
```

## API Endpoints

### GET /
Returns the home page with search bar and state controls.

**Response:** HTML page with:
- Search input field
- Current state display (0, 1, or 2)
- Three state buttons to switch modes

---

### GET /search?q=<query>
Main search endpoint that processes the query based on current vulnerability state.

**Parameters:**
- `q` (string, required): The search query string

**Response:** HTML page showing:
- Current state (0, 1, or 2)
- Original query (escaped for display)
- Processed result (based on current state)

**Examples:**
```
GET /search?q=hello
GET /search?q=%3Cscript%3Ealert('XSS')%3C/script%3E
GET /search?q=%3Cimg%20src=x%20onerror=%22alert('XSS')%22%3E
```

**Behavior by State:**
- **State 2** (MAKE_VULNERABLE): Query displayed as-is, all HTML/scripts execute
- **State 1** (FIX_PARTIALLY): Query filtered except `<script>` tags remain
- **State 0** (FIX_COMPLETELY): All HTML tags removed, completely sanitized

---

### GET /api/state
Returns the current vulnerability state.

**Response:**
```json
{
  "state": "MAKE_VULNERABLE"
}
```

Or with encoded values in the frontend, the internal state is always returned in full form.

---

### POST /api/state
Updates the vulnerability state.

**Request Body:**
```json
{
  "state": "FIX_COMPLETELY"
}
```

**Valid Values:**
- `MAKE_VULNERABLE`
- `FIX_PARTIALLY`
- `FIX_COMPLETELY`

**Response:**
```json
{
  "success": true,
  "state": "FIX_COMPLETELY"
}
```

**Error Response:**
```json
{
  "success": false,
  "error": "Invalid state"
}
```

---

## State Behavior Examples

### State 0 (FIX_COMPLETELY)
```
Input:  <script>alert('XSS')</script>
Output: (empty)
```

### State 1 (FIX_PARTIALLY)
```
Input:  <img src=x onerror="alert('XSS')"><script>alert('XSS2')</script>
Output: <script>alert('XSS2')</script>
```

### State 2 (MAKE_VULNERABLE)
```
Input:  <img src=x onerror="alert('XSS')">
Output: <img src=x onerror="alert('XSS')">
```

## File Structure

```
.
├── server.js              # Express backend
├── package.json           # Dependencies
├── state.json             # Current state storage
├── Dockerfile             # Docker config
├── docker-compose.yml     # Docker Compose config
├── public/
│   ├── index.html         # Home page (simple UI)
│   └── style.css          # (unused - no styles)
├── README.md              # This file
└── TEST_CASES.md          # Detailed test cases and payloads
```

## Technologies

- **Backend:** Node.js, Express.js
- **Sanitization:** DOMPurify (for FIX_COMPLETELY state)
- **Containerization:** Docker

## Testing

See `TEST_CASES.md` for comprehensive test payloads and expected results for each state.

## Educational Use Only

This application intentionally contains security vulnerabilities for learning purposes. Do NOT use this code in production environments.
