<?php
// ShopFlux internal admin panel.
// Reachable only on the internal_net Docker network (no host port).
// Get here via SSRF from /webhooks/test on the main app, or via the
// /api/internal/admin-proxy gadget once you've leaked the internal token.
//
// Vulnerabilities:
//   - PHP unserialize() of a user-controlled cookie (`prefs`)
//   - LFI via ?page= include (no allowlist)
//   - "diagnostics" runs ping with shell metacharacters (command injection)
//   - Hard-coded basic-auth that's findable in /backups/admin.tar.gz on the
//     edge (information disclosure → admin access).

$FLAG_DIR = getenv("FLAG_DIR") ?: "/flags";
function readFlag($name) {
    global $FLAG_DIR;
    $p = "$FLAG_DIR/$name.flag";
    return is_readable($p) ? trim(file_get_contents($p))
                           : "FLAG{missing-$name}";
}

// Basic-auth gate (very weak)
$user = getenv("ADMIN_USER") ?: "shopadmin";
$pass = getenv("ADMIN_PASS") ?: "Pa55w0rd!shop";
if (!isset($_SERVER["PHP_AUTH_USER"])
    || $_SERVER["PHP_AUTH_USER"] !== $user
    || $_SERVER["PHP_AUTH_PW"]   !== $pass) {
    header('WWW-Authenticate: Basic realm="shopflux-admin"');
    header("HTTP/1.1 401 Unauthorized");
    echo "Auth required";
    exit;
}

class Preferences {
    public $theme = "light";
    public $lang  = "en";
    public $cmd   = null;          // gadget hook
    public function __wakeup() {
        if ($this->cmd) {
            // Deliberate gadget: reconstructed object can run arbitrary cmd
            $out = shell_exec($this->cmd . " 2>&1");
            echo "<!--gadget-output:\n" . htmlentities($out) . "\n-->";
            $GLOBALS["DESER_FLAG"] = readFlag("deser_php");
        }
    }
}

// Honor the prefs cookie (insecure deserialization)
if (!empty($_COOKIE["prefs"])) {
    $raw = base64_decode($_COOKIE["prefs"]);
    @unserialize($raw);             // <-- vulnerable
}

$page = $_GET["page"] ?? "home";
?>
<!doctype html>
<html><head><title>ShopFlux admin</title></head><body>
<h1>ShopFlux internal admin</h1>
<nav>
  <a href="?page=home">Home</a> |
  <a href="?page=diagnostics">Diagnostics</a> |
  <a href="?page=backups">Backups</a> |
  <a href="?page=health">Health</a>
</nav>
<hr>

<?php
if ($page === "diagnostics") {
    $host = $_GET["host"] ?? "";
    if ($host) {
        // Command injection: $host is concatenated into a shell command
        $cmd = "ping -c 1 -W 1 " . $host;
        $out = shell_exec($cmd . " 2>&1");
        echo "<pre>" . htmlentities($out ?? "") . "</pre>";
        if (preg_match('/(uid=|root:x:|FLAG\{)/', $out ?? "")) {
            echo "<pre class=flag>" . readFlag("cmd_injection") . "</pre>";
            // Also award admin_rce flag if attacker reached here AND ran arbitrary
            // command — it's the chain reward.
            echo "<pre class=flag>" . readFlag("admin_rce") . "</pre>";
        }
    } else {
        echo '<form><input name=page value=diagnostics type=hidden>'
            .'<input name=host placeholder=8.8.8.8>'
            .'<button>Run ping</button></form>';
    }
} elseif ($page === "backups") {
    // LFI: include arbitrary file via the `file` param
    $f = $_GET["file"] ?? "";
    if ($f) {
        // No allowlist; ../ allowed
        if (file_exists($f)) {
            echo "<pre>" . htmlentities(file_get_contents($f)) . "</pre>";
        } else {
            echo "Not found.";
        }
    } else {
        echo '<form><input name=page value=backups type=hidden>'
            .'<input name=file placeholder=/etc/passwd>'
            .'<button>Read</button></form>';
    }
} elseif ($page === "health") {
    echo "<pre>OK\n" . php_uname() . "</pre>";
} else {
    echo "<p>Welcome, " . htmlentities($_SERVER["PHP_AUTH_USER"]) . ".</p>";
    echo "<p>Send commands via diagnostics, browse backups, or health.</p>";
}

if (!empty($GLOBALS["DESER_FLAG"])) {
    echo "<pre class=flag>" . htmlentities($GLOBALS["DESER_FLAG"]) . "</pre>";
}
?>
</body></html>
