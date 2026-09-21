<?php declare(strict_types=1);

// Telegram login relay using MadelineProto, backed directly by Postgres
// (Supabase) for session storage via MadelineProto's native
// Settings\Database\Postgres backend - confirmed against the real source
// (src/Settings/Database/Postgres.php, SqlAbstract, DriverDatabaseAbstract)
// rather than assumed. This means session state survives Render redeploys
// automatically, with no custom blob-sync code needed, unlike the WaCalls
// service (which uses local SQLite and needs that solved separately).
//
// This file handles login only (phone -> code -> optional 2FA -> connected).
// Call-placing is intentionally a separate, later piece of work: an active
// call needs a connection that stays alive for its duration, which is a
// genuinely different request model than this stateless login flow, and
// rushing it in the same pass as login risks repeating the exact
// looks-like-it-works-but-isn't mistake this whole relay replaces.

require __DIR__ . '/../vendor/autoload.php';

use danog\MadelineProto\API;
use danog\MadelineProto\Settings;
use danog\MadelineProto\Settings\Database\Postgres;
use danog\MadelineProto\Settings\AppInfo;
use danog\MadelineProto\RPCError\SessionPasswordNeededError;

header('Content-Type: application/json');

// Every route requires this - matches the pattern already used for the
// other two relays (server-social/social-relay.js, WaCalls), since this
// service would otherwise be a completely open door to anyone's linked
// Telegram account.
$secret = getenv('MP_RELAY_INTERNAL_SECRET') ?: '';
$given = $_SERVER['HTTP_X_INTERNAL_SECRET'] ?? '';
if ($secret === '' || !hash_equals($secret, $given)) {
    http_response_code(401);
    echo json_encode(['error' => 'unauthorized']);
    exit;
}

function readJsonBody(): array {
    $raw = file_get_contents('php://input');
    $data = json_decode($raw ?: '{}', true);
    return is_array($data) ? $data : [];
}

function respond(int $code, array $body): never {
    http_response_code($code);
    echo json_encode($body);
    exit;
}

// One MadelineProto session per user, isolated by session name - Postgres
// storage keys its tables/rows off this name, so different users' sessions
// never collide even though they all share the same underlying database.
function sessionFor(string $userId): API {
    $settings = new Settings;
    $settings->setAppInfo(
        (new AppInfo)
            ->setApiId((int) getenv('TELEGRAM_API_ID'))
            ->setApiHash(getenv('TELEGRAM_API_HASH')),
    );
    $pg = (new Postgres)
        ->setUri(getenv('SUPABASE_DB_HOST') . ':' . (getenv('SUPABASE_DB_PORT') ?: '5432'))
        ->setUsername(getenv('SUPABASE_DB_USER'))
        ->setPassword(getenv('SUPABASE_DB_PASSWORD'))
        ->setDatabase(getenv('SUPABASE_DB_NAME') ?: 'postgres');
    $settings->setDb($pg);
    return new API('mp_session_' . $userId, $settings);
}

$method = $_SERVER['REQUEST_METHOD'];
$path = parse_url($_SERVER['REQUEST_URI'], PHP_URL_PATH);

// /sessions/{userId}/start
if ($method === 'POST' && preg_match('#^/sessions/([^/]+)/start$#', $path, $m)) {
    $userId = $m[1];
    $phone = trim(readJsonBody()['phone'] ?? '');
    if ($phone === '') respond(400, ['error' => 'phone required']);
    try {
        $mp = sessionFor($userId);
        $mp->phoneLogin($phone);
        respond(200, ['status' => 'code_sent']);
    } catch (\Throwable $e) {
        respond(500, ['error' => $e->getMessage()]);
    }
}

// /sessions/{userId}/verify
if ($method === 'POST' && preg_match('#^/sessions/([^/]+)/verify$#', $path, $m)) {
    $userId = $m[1];
    $code = trim(readJsonBody()['code'] ?? '');
    if ($code === '') respond(400, ['error' => 'code required']);
    try {
        $mp = sessionFor($userId);
        $mp->completePhoneLogin($code);
        respond(200, ['status' => 'connected']);
    } catch (SessionPasswordNeededError) {
        // This is the real, documented way MadelineProto signals 2FA is
        // required (src/RPCError/SessionPasswordNeededError.php) - not a
        // special field in completePhoneLogin's return value, which was my
        // first (wrong) guess before checking.
        respond(200, ['status' => 'need_2fa']);
    } catch (\Throwable $e) {
        respond(500, ['error' => $e->getMessage()]);
    }
}

// /sessions/{userId}/2fa
if ($method === 'POST' && preg_match('#^/sessions/([^/]+)/2fa$#', $path, $m)) {
    $userId = $m[1];
    $password = readJsonBody()['password'] ?? '';
    if ($password === '') respond(400, ['error' => 'password required']);
    try {
        $mp = sessionFor($userId);
        $mp->complete2faLogin($password);
        respond(200, ['status' => 'connected']);
    } catch (\Throwable $e) {
        respond(500, ['error' => $e->getMessage()]);
    }
}

// /sessions/{userId}/status
if ($method === 'GET' && preg_match('#^/sessions/([^/]+)/status$#', $path, $m)) {
    $userId = $m[1];
    try {
        $mp = sessionFor($userId);
        $me = $mp->getSelf();
        respond(200, ['status' => 'connected', 'username' => $me['username'] ?? null, 'firstName' => $me['first_name'] ?? null]);
    } catch (\Throwable $e) {
        // Not logged in yet, or a transient connection issue - either way,
        // this endpoint's job is to answer "are you connected", not to
        // distinguish every possible reason you aren't.
        respond(200, ['status' => 'disconnected']);
    }
}

// /sessions/{userId} (disconnect)
if ($method === 'DELETE' && preg_match('#^/sessions/([^/]+)$#', $path, $m)) {
    $userId = $m[1];
    try {
        $mp = sessionFor($userId);
        $mp->logout();
        respond(200, ['status' => 'disconnected']);
    } catch (\Throwable $e) {
        respond(200, ['status' => 'disconnected']); // already gone is a fine outcome for a disconnect request
    }
}

respond(404, ['error' => 'not found']);
