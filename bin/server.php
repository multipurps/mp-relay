<?php declare(strict_types=1);

/**
 * mp-relay persistent server.
 *
 * WHY THIS REPLACES public/index.php's `php -S` MODEL
 * ----------------------------------------------------
 * Login (start/verify/2fa/status/delete) is one request, one response - the
 * old `php -S ... public/index.php` model (spin up a fresh process, build a
 * fresh API object from Postgres session storage, do one thing, exit) works
 * fine for that.
 *
 * A live call cannot work that way: `requestCall()` returns immediately, but
 * something has to hold that call object open - polling its state, pumping
 * audio - for as long as the call runs, while OTHER requests (status checks,
 * a second call, login for a different user) keep being served. That needs
 * one persistent process with a single event loop, where the call's audio
 * pump is a background coroutine and HTTP requests are handled concurrently
 * on the same loop. amphp/http-server (a dependency MadelineProto already
 * pulls in, since MadelineProto itself is built on amphp/revolt) is exactly
 * this: a long-running async HTTP server, not a one-shot script per request.
 *
 * Every existing login route is ported here unchanged in behaviour so this
 * is a drop-in replacement, not a parallel service.
 *
 * WHAT IS GENUINELY UNVERIFIED
 * -----------------------------
 * I have no PHP interpreter with amphp/madelineproto actually installed
 * (this sandbox has no access to packagist.org to `composer install`), and
 * no live Telegram account to place a real call against. This file is
 * syntax-checked (`php -l`) but has never been run. Three specific things
 * can only be confirmed on a live call - each is marked below with
 * "UNVERIFIED":
 *   1. Whether legacy-engine `play()` accepts a raw-PCM ReadableStream via
 *      its documented realtime-conversion path, or needs a specific
 *      container/sample-rate hint.
 *   2. Whether a bare phone number (not already a mutual contact) resolves
 *      via `contacts.importContacts` at all - Telegram's privacy settings
 *      can refuse this independently of the code being correct.
 *   3. Which call engine (legacy libtgvoip vs newer WebRTC) a real 1:1 call
 *      negotiates - this changes the exact audio container on both sides.
 */

use Amp\ByteStream\ReadableStream;
use Amp\ByteStream\WritableStream;
use Amp\DeferredFuture;
use Amp\Http\HttpStatus;
use Amp\Http\Server\HttpErrorException;
use Amp\Http\Server\Request;
use Amp\Http\Server\RequestHandler\ClosureRequestHandler;
use Amp\Http\Server\Response;
use Amp\Http\Server\SocketHttpServer;
use Amp\Process\Process;
use Amp\Socket\BindContext;
use Amp\Socket\InternetAddress;
use Amp\Websocket\Client\WebsocketHandshake;
use Amp\Websocket\WebsocketCloseCode;
use danog\MadelineProto\API;
use danog\MadelineProto\MediaDestination;
use danog\MadelineProto\RPCError\SessionPasswordNeededError;
use danog\MadelineProto\Settings;
use danog\MadelineProto\Settings\AppInfo;
use danog\MadelineProto\Settings\Database\Postgres;
use danog\MadelineProto\VoIP\CallState;
use danog\MadelineProto\VoIP\DiscardReason;
use Monolog\Logger as NullPsrLoggerPlaceholder; // not used; keeps IDEs from flagging an unused-import lint on some setups
use Psr\Log\NullLogger;
use Revolt\EventLoop;

use function Amp\async;
use function Amp\delay;
use function Amp\Websocket\Client\connect;

require __DIR__ . '/../vendor/autoload.php';

// ---------------------------------------------------------------------------
// Shared config / helpers (behaviour-identical to the old public/index.php)
// ---------------------------------------------------------------------------

function envOrNull(string $key): ?string
{
    $v = getenv($key);
    return $v === false || $v === '' ? null : $v;
}

/** One MadelineProto session per user, cached for the life of this process. */
final class SessionPool
{
    /** @var array<string, API> */
    private array $sessions = [];

    public function get(string $userId): API
    {
        return $this->sessions[$userId] ??= $this->build($userId);
    }

    private function build(string $userId): API
    {
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
}

function jsonResponse(int $status, array $body): Response
{
    return new Response($status, ['content-type' => 'application/json'], json_encode($body));
}

function readJsonBody(Request $request): array
{
    $raw = $request->getBody()->buffer();
    $data = json_decode($raw ?: '{}', true);
    return is_array($data) ? $data : [];
}

// ---------------------------------------------------------------------------
// ACAF v1 framing - must match pipecat-service/app/protocol.py exactly.
// Header: magic(4) version(1) type(1) encoding(1) channels(1) sample_rate(4,
// LE) sequence(4, LE) timestamp_ms(8, LE) payload_len(4, LE) = 28 bytes.
// PHP's pack() 'I'/'Q' are NATIVE byte order, not little-endian - this uses
// 'V' (uint32 LE) and 'P' (uint64 LE), which is the actual fix needed versus
// the sketch in docs/MP-RELAY-INTEGRATION.md.
// ---------------------------------------------------------------------------

final class AcafFrameType
{
    public const AUDIO_IN = 1;
    public const AUDIO_OUT = 2;
    public const PARTIAL_TRANSCRIPT = 3;
    public const INTERRUPT = 4;
    public const HEARTBEAT = 5;
}

final class AcafEncoding
{
    public const PCM_S16LE = 1;
    public const MULAW = 2;
    public const OGG_OPUS = 3;
}

function acafPack(int $type, int $sampleRate, int $sequence, string $payload): string
{
    return pack(
        'a4CCCCVVPV',
        'ACAF',
        1,                          // version
        $type,
        AcafEncoding::PCM_S16LE,
        1,                          // channels
        $sampleRate,
        $sequence,
        (int) round(microtime(true) * 1000),
        strlen($payload),
    ) . $payload;
}

/** @return array{type:int,encoding:int,channels:int,sample_rate:int,sequence:int,timestamp_ms:int,payload:string} */
function acafUnpack(string $data): array
{
    if (strlen($data) < 28) {
        throw new RuntimeException('short ACAF frame');
    }
    $h = unpack('a4magic/Cversion/Ctype/Cencoding/Cchannels/Vrate/Vseq/Pts/Vlen', $data);
    if ($h === false || $h['magic'] !== 'ACAF') {
        throw new RuntimeException('bad ACAF magic');
    }
    $payload = substr($data, 28, $h['len']);
    if (strlen($payload) !== $h['len']) {
        throw new RuntimeException('truncated ACAF payload');
    }
    return [
        'type' => $h['type'],
        'encoding' => $h['encoding'],
        'channels' => $h['channels'],
        'sample_rate' => $h['rate'],
        'sequence' => $h['seq'],
        'timestamp_ms' => $h['ts'],
        'payload' => $payload,
    ];
}

// ---------------------------------------------------------------------------
// A ReadableStream that Telegram's play() pulls from. Frames are pushed in
// as they arrive from the assistant over the WebSocket; `interrupt()` drops
// everything not yet handed to Telegram (barge-in). This is hand-written
// against Amp\DeferredFuture / Amp\ByteStream\ReadableStream rather than
// amphp/pipeline's Queue, specifically so interrupt can clear pending data -
// Queue has no such operation.
// ---------------------------------------------------------------------------
final class OutboundAudioSource implements ReadableStream
{
    /** @var \SplQueue<string> */
    private \SplQueue $pending;
    private ?DeferredFuture $waiting = null;
    private bool $closed = false;

    public function __construct()
    {
        $this->pending = new \SplQueue();
    }

    public function push(string $bytes): void
    {
        if ($this->closed) {
            return;
        }
        $this->pending->push($bytes);
        if ($this->waiting !== null) {
            $w = $this->waiting;
            $this->waiting = null;
            $w->complete();
        }
    }

    /** Barge-in: drop everything not yet pulled by Telegram. */
    public function interrupt(): void
    {
        while (!$this->pending->isEmpty()) {
            $this->pending->shift();
        }
    }

    public function read(?\Amp\Cancellation $cancellation = null): ?string
    {
        while ($this->pending->isEmpty()) {
            if ($this->closed) {
                return null;
            }
            $this->waiting = new DeferredFuture();
            $this->waiting->getFuture()->await($cancellation);
        }
        return $this->pending->shift();
    }

    public function isReadable(): bool
    {
        return !$this->closed;
    }

    public function close(): void
    {
        $this->closed = true;
        if ($this->waiting !== null) {
            $w = $this->waiting;
            $this->waiting = null;
            $w->complete();
        }
    }
}

/**
 * A WritableStream that Telegram's setOutput() writes the caller's raw OGG
 * Opus audio into. Just forwards every chunk to a callback - the ffmpeg
 * decode happens outside this class (see CallBridge::pumpInbound).
 */
final class ForwardingSink implements WritableStream
{
    private bool $closed = false;

    public function __construct(private readonly \Closure $onChunk)
    {
    }

    public function write(string $bytes): void
    {
        if (!$this->closed) {
            ($this->onChunk)($bytes);
        }
    }

    public function end(): void
    {
        $this->closed = true;
    }

    public function close(): void
    {
        $this->closed = true;
    }

    public function isClosed(): bool
    {
        return $this->closed;
    }
}

// ---------------------------------------------------------------------------
// One Telegram call, bridged to the Pipecat assistant.
// ---------------------------------------------------------------------------
final class CallBridge
{
    public string $status = 'ringing'; // ringing | connected | ended | failed
    public ?string $discardReason = null;
    private int $outSeq = 0;
    private bool $stopping = false;
    private ?Process $decodeProc = null;

    public function __construct(
        private readonly \danog\MadelineProto\EventHandler\Calls\PrivateCall $call,
        private readonly int $callId,
        private readonly string $sessionId,
        private readonly string $bridgeUrl,
        private readonly string $bridgeSecret,
        private readonly int $bridgeSampleRate,
    ) {
    }

    /** Runs for the life of the call. Never throws - failures set status=failed. */
    public function run(): void
    {
        try {
            $handshake = (new WebsocketHandshake($this->bridgeUrl))
                ->withHeader('X-Assistant-Session', $this->sessionId);
            $connection = connect($handshake);
            $connection->sendText(json_encode([
                'type' => 'hello',
                'sessionId' => $this->sessionId,
                'platform' => 'telegram',
                'sampleRate' => $this->bridgeSampleRate,
                'channels' => 1,
                'encoding' => 'pcm_s16le',
                'secret' => $this->bridgeSecret,
            ], JSON_THROW_ON_ERROR));

            $outbound = new OutboundAudioSource();

            // Outbound: assistant's speech -> Telegram.
            // UNVERIFIED: this assumes the legacy engine's realtime-conversion
            // path (Tools::canConvertOgg(), which needs ffmpeg + the FFI
            // extension present in the image) accepts a raw PCM16 stream
            // directly. If a live call throws "please pre-convert it using
            // ... ffmpeg", this is the line that needs a manual PCM->OGG
            // Opus encode step in front of it instead.
            $this->call->play($outbound, MediaDestination::Camera);

            // Inbound: caller's speech -> assistant. setOutput() hands us
            // raw OGG Opus bytes (MadelineProto's own docs: "pipe OGG OPUS
            // audio data to ffmpeg...") - we decode with a real ffmpeg
            // subprocess, not a guessed shortcut.
            $this->startInboundDecoder($connection);
            $this->call->setOutput(new ForwardingSink(function (string $chunk): void {
                if ($this->decodeProc !== null) {
                    try {
                        $this->decodeProc->getStdin()->write($chunk);
                    } catch (\Throwable) {
                        // decoder died; inbound audio for this call is lost,
                        // but the call itself keeps running.
                    }
                }
            }));

            async(fn () => $this->watchCallState());

            // Read control + AUDIO_OUT frames from the assistant until the
            // call ends.
            foreach ($connection as $message) {
                if ($this->stopping) {
                    break;
                }
                if ($message->isText()) {
                    $this->handleControl($outbound, json_decode($message->buffer(), true) ?: []);
                } else {
                    $frame = acafUnpack($message->buffer());
                    if ($frame['type'] === AcafFrameType::AUDIO_OUT) {
                        $outbound->push($frame['payload']);
                    } elseif ($frame['type'] === AcafFrameType::INTERRUPT) {
                        $outbound->interrupt();
                    }
                    // HEARTBEAT frames need no action beyond having been read.
                }
            }
            $outbound->close();
            $connection->close(WebsocketCloseCode::NORMAL_CLOSE, 'call ended');
        } catch (\Throwable $e) {
            error_log('[call ' . $this->callId . '] bridge failed: ' . $e->getMessage());
            $this->status = 'failed';
        } finally {
            $this->decodeProc?->kill();
        }
    }

    private function handleControl(OutboundAudioSource $outbound, array $msg): void
    {
        switch ($msg['type'] ?? null) {
            case 'ready':
                $this->status = 'connected';
                break;
            case 'ping':
                // handled by the underlying websocket connection's own pong;
                // amphp/websocket answers protocol-level pings automatically.
                break;
            case 'interrupt':
                $outbound->interrupt();
                break;
            case 'hangup':
            case 'stopped':
                $this->requestStop('assistant ended the call');
                break;
        }
    }

    /** ffmpeg: OGG Opus in on stdin -> raw PCM16 mono at bridgeSampleRate out on stdout. */
    private function startInboundDecoder(\Amp\Websocket\WebsocketConnection $connection): void
    {
        $proc = Process::start([
            'ffmpeg', '-hide_banner', '-loglevel', 'error',
            '-f', 'ogg', '-i', 'pipe:0',
            '-f', 's16le', '-ar', (string) $this->bridgeSampleRate, '-ac', '1',
            'pipe:1',
        ]);
        $this->decodeProc = $proc;
        async(function () use ($proc, $connection): void {
            $stdout = $proc->getStdout();
            while (($chunk = $stdout->read()) !== null) {
                if ($chunk === '') {
                    continue;
                }
                $connection->sendBinary(acafPack(AcafFrameType::AUDIO_IN, $this->bridgeSampleRate, $this->outSeq++, $chunk));
            }
        });
    }

    /** Polls Telegram's own call state (not the assistant's) to catch a real hangup. */
    private function watchCallState(): void
    {
        $api = $this->call->getAPI();
        while (!$this->stopping) {
            delay(1.0);
            $state = $api->getCallState($this->callId);
            if ($state === null || $state === CallState::ENDED) {
                $this->requestStop('telegram call ended');
                return;
            }
        }
    }

    private function requestStop(string $reason): void
    {
        if ($this->stopping) {
            return;
        }
        $this->stopping = true;
        $this->status = 'ended';
        error_log('[call ' . $this->callId . '] stopping: ' . $reason);
    }

    public function hangup(): void
    {
        $this->requestStop('hangup requested');
        try {
            $this->call->discard(DiscardReason::HANGUP);
        } catch (\Throwable) {
            // already gone is fine
        }
    }
}

// ---------------------------------------------------------------------------
// Bootstrap
// ---------------------------------------------------------------------------

$secret = getenv('MP_RELAY_INTERNAL_SECRET') ?: '';
$bridgeUrl = getenv('ASSISTANT_BRIDGE_URL') ?: '';
$bridgeSecret = getenv('ASSISTANT_BRIDGE_SECRET') ?: '';
$bridgeSampleRate = (int) (getenv('ASSISTANT_BRIDGE_SAMPLE_RATE') ?: 16000);

$pool = new SessionPool();
/** @var array<string, CallBridge> */
$activeCalls = [];

$requireSecret = static function (Request $request) use ($secret): void {
    $given = $request->getHeader('X-Internal-Secret') ?? '';
    if ($secret === '' || !hash_equals($secret, $given)) {
        throw new HttpErrorException(HttpStatus::UNAUTHORIZED, 'unauthorized');
    }
};

$handler = new ClosureRequestHandler(function (Request $request) use ($pool, &$activeCalls, $requireSecret, $bridgeUrl, $bridgeSecret, $bridgeSampleRate): Response {
    $method = $request->getMethod();
    $path = $request->getUri()->getPath();

    // GET /healthz - liveness only, no secret required (matches the spec:
    // "GET /healthz -> liveness (no secret)"), so an uptime pinger doesn't
    // need the internal secret embedded in it.
    if ($method === 'GET' && $path === '/healthz') {
        return jsonResponse(200, ['status' => 'ok']);
    }

    try {
        $requireSecret($request);

        // ---- existing login routes, ported unchanged ----
        if ($method === 'POST' && preg_match('#^/sessions/([^/]+)/start$#', $path, $m)) {
            $phone = trim(readJsonBody($request)['phone'] ?? '');
            if ($phone === '') return jsonResponse(400, ['error' => 'phone required']);
            $mp = $pool->get($m[1]);
            $mp->phoneLogin($phone);
            return jsonResponse(200, ['status' => 'code_sent']);
        }
        if ($method === 'POST' && preg_match('#^/sessions/([^/]+)/verify$#', $path, $m)) {
            $code = trim(readJsonBody($request)['code'] ?? '');
            if ($code === '') return jsonResponse(400, ['error' => 'code required']);
            try {
                $pool->get($m[1])->completePhoneLogin($code);
                return jsonResponse(200, ['status' => 'connected']);
            } catch (SessionPasswordNeededError) {
                return jsonResponse(200, ['status' => 'need_2fa']);
            }
        }
        if ($method === 'POST' && preg_match('#^/sessions/([^/]+)/2fa$#', $path, $m)) {
            $password = readJsonBody($request)['password'] ?? '';
            if ($password === '') return jsonResponse(400, ['error' => 'password required']);
            $pool->get($m[1])->complete2faLogin($password);
            return jsonResponse(200, ['status' => 'connected']);
        }
        if ($method === 'GET' && preg_match('#^/sessions/([^/]+)/status$#', $path, $m)) {
            try {
                $me = $pool->get($m[1])->getSelf();
                return jsonResponse(200, ['status' => 'connected', 'username' => $me['username'] ?? null, 'firstName' => $me['first_name'] ?? null]);
            } catch (\Throwable) {
                return jsonResponse(200, ['status' => 'disconnected']);
            }
        }
        if ($method === 'DELETE' && preg_match('#^/sessions/([^/]+)$#', $path, $m)) {
            try {
                $pool->get($m[1])->logout();
            } catch (\Throwable) {
                // already gone is fine
            }
            return jsonResponse(200, ['status' => 'disconnected']);
        }

        // ---- new call routes ----
        if ($method === 'POST' && $path === '/calls') {
            if ($bridgeUrl === '' || $bridgeSecret === '') {
                return jsonResponse(500, ['error' => 'ASSISTANT_BRIDGE_URL / ASSISTANT_BRIDGE_SECRET not configured']);
            }
            $body = readJsonBody($request);
            $userId = trim((string) ($body['userId'] ?? ''));
            $to = trim((string) ($body['to'] ?? ''));
            if ($userId === '' || $to === '') {
                return jsonResponse(400, ['error' => 'userId and to are required']);
            }
            $mp = $pool->get($userId);

            // Resolve a phone number to a Telegram user id first - a bare
            // phone number is not directly callable. UNVERIFIED: Telegram's
            // privacy settings can make this resolve to nothing even when
            // the number is correct and does have a Telegram account.
            $target = $to;
            if (preg_match('/^\+?[0-9]{6,15}$/', $to)) {
                try {
                    $imported = $mp->contacts->importContacts(contacts: [[
                        '_' => 'inputPhoneContact',
                        'client_id' => 0,
                        'phone' => $to,
                        'first_name' => 'Call',
                        'last_name' => '',
                    ]]);
                } catch (\Throwable $e) {
                    return jsonResponse(502, ['error' => 'contact import failed: ' . $e->getMessage()]);
                }
                $users = $imported['users'] ?? [];
                if (!$users) {
                    return jsonResponse(422, ['error' => 'This number could not be resolved on Telegram - it may not have an account, or its privacy settings block discovery by phone number.']);
                }
                $target = $users[0]['id'];
            }

            try {
                $call = $mp->requestCall($target);
            } catch (\Throwable $e) {
                return jsonResponse(502, ['error' => 'requestCall failed: ' . $e->getMessage()]);
            }

            $callId = (string) $call->callID;
            $sessionId = 'call-' . $callId;
            $bridge = new CallBridge($call, $call->callID, $sessionId, $bridgeUrl, $bridgeSecret, $bridgeSampleRate);
            $activeCalls[$callId] = $bridge;
            async(function () use ($bridge, $callId, &$activeCalls): void {
                $bridge->run();
                // Keep the record around briefly so a status check right
                // after the call ends still gets an answer, then drop it.
                async(function () use ($callId, &$activeCalls): void {
                    delay(30.0);
                    unset($activeCalls[$callId]);
                });
            });

            return jsonResponse(200, ['callId' => $callId, 'status' => 'ringing']);
        }

        if ($method === 'GET' && preg_match('#^/calls/([^/]+)$#', $path, $m)) {
            $bridge = $activeCalls[$m[1]] ?? null;
            if ($bridge === null) {
                return jsonResponse(404, ['error' => 'not found']);
            }
            return jsonResponse(200, ['callId' => $m[1], 'status' => $bridge->status, 'discardReason' => $bridge->discardReason]);
        }

        if ($method === 'DELETE' && preg_match('#^/calls/([^/]+)$#', $path, $m)) {
            $bridge = $activeCalls[$m[1]] ?? null;
            if ($bridge === null) {
                return jsonResponse(200, ['status' => 'ended']); // already gone is fine
            }
            $bridge->hangup();
            return jsonResponse(200, ['status' => 'ended']);
        }
    } catch (HttpErrorException $e) {
        return jsonResponse($e->getStatus(), ['error' => $e->getReason() ?: 'error']);
    } catch (\Throwable $e) {
        error_log('unhandled: ' . $e->getMessage());
        return jsonResponse(500, ['error' => $e->getMessage()]);
    }

    return jsonResponse(404, ['error' => 'not found']);
});

$server = SocketHttpServer::createForDirectAccess(new class extends \Psr\Log\AbstractLogger {
    public function log($level, \Stringable|string $message, array $context = []): void
    {
        error_log((string) $level . ': ' . $message);
    }
});
$server->expose(new InternetAddress('0.0.0.0', (int) (getenv('PORT') ?: 10000)));
$server->start($handler, new \Amp\Http\Server\DefaultErrorHandler());

// Keep the process alive - the HTTP server and every call's background
// coroutine all run on this same Revolt event loop.
EventLoop::run();
