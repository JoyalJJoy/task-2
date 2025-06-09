 

---

## 1 · Database schema (MySQL)

```sql
CREATE DATABASE IF NOT EXISTS user_auth
  CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

USE user_auth;

CREATE TABLE users (
    id         INT UNSIGNED      NOT NULL AUTO_INCREMENT,
    username   VARCHAR(50)       NOT NULL UNIQUE,
    email      VARCHAR(120)      NOT NULL UNIQUE,
    password   CHAR(60)          NOT NULL,        -- bcrypt hash length
    created_at TIMESTAMP         NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (id)
) ENGINE=InnoDB;
```

**Diagram-in-words**

```
users
├── id (PK)
├── username  ← unique index
├── email     ← unique index
└── password  ← bcrypt hash
```

> **Why `CHAR(60)`?** `password_hash()` with the default `PASSWORD_BCRYPT` returns a 60-character string.
> **Why `utf8mb4`?** Full Unicode and emojis without surprises.

---

## 2 · Recommended folder structure

```
/project-root
│
├─ public/                 ← All web-accessible files
│   ├─ index.php           ← Redirect to login if not authenticated
│   ├─ login.php
│   ├─ signup.php
│   ├─ dashboard.php       ← Protected page example
│   └─ logout.php
│
├─ src/
│   ├─ config.php          ← DB credentials & PDO instance
│   ├─ User.php            ← Lightweight user model / helper functions
│   └─ auth.php            ← Common auth utilities (isLoggedIn, requireLogin)
│
├─ vendor/                 ← Composer packages (optional)
│
└─ assets/
    ├─ css/
    │   └─ styles.css
    └─ img/
```

*Place **no** credentials or business logic in `public/`; keep it in `src/`.*

---

## 3 · Core PHP snippets

### 3.1 · `src/config.php` — connection & session

```php
<?php
declare(strict_types=1);

session_start([
    'cookie_httponly' => true,
    'cookie_secure'   => isset($_SERVER['HTTPS']),
    'cookie_samesite' => 'Lax',
]);

$DB_HOST = 'localhost';
$DB_NAME = 'user_auth';
$DB_USER = 'your_mysql_user';
$DB_PASS = 'your_mysql_pass';

$pdo = new PDO(
    "mysql:host=$DB_HOST;dbname=$DB_NAME;charset=utf8mb4",
    $DB_USER,
    $DB_PASS,
    [PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION]
);
```

### 3.2 · `src/User.php` — minimal helper

```php
<?php
class User
{
    public static function exists(PDO $db, string $field, string $value): bool
    {
        $stmt = $db->prepare("SELECT 1 FROM users WHERE $field = ?");
        $stmt->execute([$value]);
        return (bool) $stmt->fetchColumn();
    }

    public static function create(PDO $db, string $username, string $email, string $password): bool
    {
        $hash = password_hash($password, PASSWORD_BCRYPT);
        $stmt = $db->prepare(
            "INSERT INTO users (username, email, password) VALUES (?, ?, ?)"
        );
        return $stmt->execute([$username, $email, $hash]);
    }

    public static function verify(PDO $db, string $login, string $password): ?array
    {
        $stmt = $db->prepare(
            "SELECT id, username, email, password FROM users
             WHERE username = ? OR email = ? LIMIT 1"
        );
        $stmt->execute([$login, $login]);
        $user = $stmt->fetch(PDO::FETCH_ASSOC);
        if ($user && password_verify($password, $user['password'])) {
            return $user;
        }
        return null;
    }
}
```

### 3.3 · `public/signup.php` — sign-up handler

```php
<?php
require_once __DIR__ . '/../src/config.php';
require_once __DIR__ . '/../src/User.php';

$errors = [];
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $u = trim($_POST['username'] ?? '');
    $e = trim($_POST['email'] ?? '');
    $p = $_POST['password'] ?? '';
    $c = $_POST['confirm_password'] ?? '';

    // 1. Basic validation
    if (!$u || !$e || !$p || !$c)          $errors[] = 'All fields are required';
    if (!filter_var($e, FILTER_VALIDATE_EMAIL)) $errors[] = 'Invalid email format';
    if ($p !== $c)                         $errors[] = 'Passwords do not match';
    if (strlen($p) < 8)                    $errors[] = 'Password must be ≥ 8 chars';

    // 2. Uniqueness check
    if (!$errors && (User::exists($pdo, 'username', $u) || User::exists($pdo, 'email', $e))) {
        $errors[] = 'Username or Email already exists';
    }

    // 3. Create user
    if (!$errors && User::create($pdo, $u, $e, $p)) {
        header('Location: login.php?signup=success');
        exit;
    }
}
?>
<!-- below is the HTML form (trimmed for brevity) -->
```

### 3.4 · `public/login.php` — login handler

```php
<?php
require_once __DIR__ . '/../src/config.php';
require_once __DIR__ . '/../src/User.php';

$errors = [];
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $login = trim($_POST['login'] ?? '');
    $pass  = $_POST['password'] ?? '';

    if (!$login || !$pass) {
        $errors[] = 'Both fields are required';
    } else {
        $user = User::verify($pdo, $login, $pass);
        if ($user) {
            $_SESSION['user'] = [
                'id'       => $user['id'],
                'username' => $user['username'],
                'email'    => $user['email']
            ];
            header('Location: dashboard.php');
            exit;
        }
        $errors[] = 'Incorrect username/email or password';
    }
}
?>
<!-- login form markup -->
```

### 3.5 · `src/auth.php` — gate-keeper

```php
<?php
function requireLogin(): void
{
    if (empty($_SESSION['user'])) {
        header('Location: /public/login.php?msg=please+login');
        exit;
    }
}

function logout(): void
{
    $_SESSION = [];
    session_destroy();
}
```

Add `require_once '../src/auth.php'; requireLogin();` at the top of any protected page.

---

## 4 · Lightweight CSS (assets/css/styles.css)

```css
body {
  font-family: system-ui, sans-serif;
  background: #f7f7f7;
  display: flex; align-items: center; justify-content: center;
  min-height: 100vh; margin: 0;
}

form {
  background: #fff; padding: 2rem 2.5rem;
  max-width: 400px; width: 100%;
  border-radius: 8px; box-shadow: 0 4px 10px rgba(0,0,0,0.06);
}

input[type=text], input[type=email], input[type=password] {
  width: 100%; padding: .75rem; margin: .5rem 0 1.25rem;
  border: 1px solid #ccc; border-radius: 4px;
}

button {
  width: 100%; padding: .75rem;
  border: none; border-radius: 4px;
  background: #007bff; color: #fff; font-weight: 600;
  cursor: pointer;
}
button:hover { background: #0056c7; }
.error { color: #cc0000; margin-bottom: 1rem; }
```

---

## 5 · Security & UX checklist

| Area                     | Checklist                                                                       |
| ------------------------ | ------------------------------------------------------------------------------- |
| **Passwords**            | `password_hash()`, `password_verify()`, **never** store plain text              |
| **SQL Injection**        | Always use **prepared statements** (PDO placeholders)                           |
| **Sessions**             | `session_start()` *before* output, set `httponly`, `samesite`, `secure` cookies |
| **Rate limiting / CSRF** | For production, add CSRF tokens and throttle login attempts                     |
| **HTTPS**                | Deploy behind TLS; the `cookie_secure` flag in `session_start` auto-detects     |
| **Validation feedback**  | Display collected errors in one list; keep success messages distinct            |
| **Redirect logic**       | After login, redirect either to last-requested page or a common dashboard       |



 
