# XSS Vulnerability Test Cases

This document outlines the three test cases for demonstrating XSS vulnerability across all three states.

## State Encoding

- **0** = FIX_COMPLETELY (Fully Fixed - Complete Sanitization)
- **1** = FIX_PARTIALLY (Partially Fixed - Script Tags Allowed)
- **2** = MAKE_VULNERABLE (Not Fixed - Fully Vulnerable)

---

## Test Case 1: Basic Script Tag Injection

### State: 2 (MAKE_VULNERABLE)

**Test Payload:**
```
<script>alert('XSS')</script>
```

**Expected Behavior:**
- Script tag appears in the result area
- In a real browser, the alert would execute
- Shows full XSS vulnerability

**What Happens:**
- Input is displayed as-is without any sanitization
- HTML is rendered directly in the page
- JavaScript would execute

---

## Test Case 2: Image Tag with Event Handler

### State: 2 (MAKE_VULNERABLE)

**Test Payload:**
```
<img src=x onerror="alert('XSS')">
```

**Expected Behavior:**
- Image tag with onerror handler appears in result
- In a real browser, the alert would execute immediately
- Alternative XSS vector is exposed

**What Happens:**
- Event handlers are preserved
- Image fails to load, triggering onerror
- JavaScript executes via event handler

---

## Test Case 3: Mixed HTML and Script Tags

### State: 1 (FIX_PARTIALLY)

**Test Payload:**
```
<img src=x onerror="alert('XSS')"><script>alert('XSS2')</script>
```

**Expected Behavior:**
- Image tag is removed (other HTML tags are filtered)
- Script tag remains in the result
- Demonstrates incomplete fix - script tags still allowed

**What Happens:**
- `<img>` tag is stripped out (partial fix for other tags)
- `<script>alert('XSS2')</script>` remains intact
- This shows why FIX_PARTIALLY is dangerous

---

## Test Case 4: Full Sanitization Test

### State: 0 (FIX_COMPLETELY)

**Test Payload:**
```
<script>alert('XSS')</script>
```

**Expected Behavior:**
- Result area is empty or shows plain text only
- No HTML tags appear
- Complete protection against XSS

**What Happens:**
- All HTML tags are removed
- Content is completely sanitized
- Safe to display in any context

---

## Test Case 5: Comprehensive XSS Vectors Test

### State: 1 (FIX_PARTIALLY)

**Test Payload:**
```
<svg onload="alert('XSS')"><img src=x onerror="alert('XSS')"><script>alert('XSS')</script>
```

**Expected Behavior:**
- SVG tag removed
- Img tag removed
- Script tag remains
- Only the script tag passes through the partial filter

**What Happens:**
- Non-script HTML tags are filtered out
- Script tag is explicitly allowed through
- Demonstrates the vulnerability of FIX_PARTIALLY

---

## Testing Workflow

1. **Start at State 2 (MAKE_VULNERABLE)**
   - Click button "2" to set state to MAKE_VULNERABLE
   - Current State shows: 2
   - Try Test Payload 1 or 2

2. **Switch to State 1 (FIX_PARTIALLY)**
   - Click button "1" to set state to FIX_PARTIALLY
   - Current State shows: 1
   - Try Test Payload 3 or 5
   - Notice how script tags still get through

3. **Switch to State 0 (FIX_COMPLETELY)**
   - Click button "0" to set state to FIX_COMPLETELY
   - Current State shows: 0
   - Try any of the payloads
   - Notice complete sanitization

---

## Summary Table

| Test | Payload | State | Expected Result |
|------|---------|-------|-----------------|
| 1 | `<script>alert('XSS')</script>` | 2 | Script tag visible, would execute |
| 2 | `<img src=x onerror="alert('XSS')">` | 2 | Image tag visible, would execute |
| 3 | `<img src=x onerror="alert('XSS')"><script>alert('XSS2')</script>` | 1 | Img removed, script remains |
| 4 | `<script>alert('XSS')</script>` | 0 | All tags removed, empty result |
| 5 | `<svg onload="alert('XSS')"><img src=x onerror="alert('XSS')"><script>alert('XSS')</script>` | 1 | SVG/Img removed, script remains |

---

## Key Observations

### State 2 (MAKE_VULNERABLE)
✗ No protection
✗ All XSS vectors execute
✗ Dangerous for production

### State 1 (FIX_PARTIALLY)
⚠️ Partial protection
⚠️ Script tags still allowed through
⚠️ False sense of security
⚠️ Still vulnerable to XSS

### State 0 (FIX_COMPLETELY)
✓ Complete protection
✓ All HTML stripped
✓ Safe for production
✓ Uses DOMPurify for sanitization

---

## Additional Payloads to Try

Feel free to experiment with these additional XSS vectors:

```
<!-- Event handler variations -->
<body onload="alert('XSS')">

<!-- SVG vectors -->
<svg/onload="alert('XSS')">

<!-- Data URI vectors -->
<a href="javascript:alert('XSS')">click</a>

<!-- HTML5 vectors -->
<input onfocus="alert('XSS')" autofocus>

<!-- Iframe vectors -->
<iframe src="javascript:alert('XSS')"></iframe>

<!-- Base tag vector -->
<base href="javascript:alert('XSS')//">

<!-- Form action vector -->
<form action="javascript:alert('XSS')"><input type="submit">
```

Each payload will behave differently depending on which state you're in!
