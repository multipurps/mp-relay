<?php declare(strict_types=1);

/**
 * Keeps every linked account's login in Supabase Postgres so a deploy/restart never logs anyone out.
 *
 * MadelineProto's login lives in a session directory on local disk (the container's disk is wiped on
 * every deploy). This stores a gzip'd tar of that directory per (provider, user) and restores it before
 * the session is opened. Saves happen after a login completes, periodically while the file set changes,
 * and when the process is told to stop.
 */
final class SessionStore
{
    private ?\PDO $pdo = null;
    /** @var array<string,string> last archive hash saved per key, to skip unchanged saves */
    private array $saved = [];

    public function __construct(private readonly string $provider = 'telegram') {}

    public function enabled(): bool
    {
        return getenv('SUPABASE_DB_HOST') !== false && getenv('SUPABASE_DB_HOST') !== '';
    }

    private function db(): \PDO
    {
        if ($this->pdo === null) {
            $dsn = sprintf(
                'pgsql:host=%s;port=%s;dbname=%s;sslmode=require',
                getenv('SUPABASE_DB_HOST'),
                getenv('SUPABASE_DB_PORT') ?: '5432',
                getenv('SUPABASE_DB_NAME') ?: 'postgres',
            );
            $this->pdo = new \PDO($dsn, (string) getenv('SUPABASE_DB_USER'), (string) getenv('SUPABASE_DB_PASSWORD'), [
                \PDO::ATTR_ERRMODE => \PDO::ERRMODE_EXCEPTION,
            ]);
            $this->pdo->exec(
                'create table if not exists linked_account_sessions (' .
                'provider text not null, user_id text not null, archive text not null, ' .
                'sha text not null, updated_at timestamptz not null default now(), ' .
                'primary key (provider, user_id))'
            );
            $this->pdo->exec('alter table linked_account_sessions enable row level security');
        }
        return $this->pdo;
    }

    /** Restore the session directory from Supabase if it is missing locally. Returns true if restored. */
    public function restore(string $userId, string $baseDir, string $name): bool
    {
        if (!$this->enabled() || file_exists($baseDir . '/' . $name)) {
            return false;
        }
        try {
            $st = $this->db()->prepare('select archive from linked_account_sessions where provider = ? and user_id = ?');
            $st->execute([$this->provider, $userId]);
            $b64 = $st->fetchColumn();
            if (!is_string($b64) || $b64 === '') {
                return false;
            }
            $tmp = tempnam(sys_get_temp_dir(), 'sess');
            file_put_contents($tmp, base64_decode($b64, true) ?: '');
            exec('tar -xzf ' . escapeshellarg($tmp) . ' -C ' . escapeshellarg($baseDir) . ' 2>&1', $out, $rc);
            @unlink($tmp);
            error_log("[sessions] restored {$this->provider} session for user from Supabase rc=$rc");
            return $rc === 0;
        } catch (\Throwable $e) {
            error_log('[sessions] restore failed: ' . $e->getMessage());
            return false;
        }
    }

    /** Save the session directory to Supabase. Skips if unchanged. */
    public function save(string $userId, string $baseDir, string $name): bool
    {
        if (!$this->enabled() || !file_exists($baseDir . '/' . $name)) {
            return false;
        }
        try {
            $tmp = tempnam(sys_get_temp_dir(), 'sess');
            exec('tar -czf ' . escapeshellarg($tmp) . ' -C ' . escapeshellarg($baseDir) . ' ' . escapeshellarg($name) . ' 2>&1', $out, $rc);
            if ($rc !== 0) {
                @unlink($tmp);
                return false;
            }
            $raw = (string) file_get_contents($tmp);
            @unlink($tmp);
            $sha = hash('sha256', $raw);
            $key = $this->provider . ':' . $userId;
            if (($this->saved[$key] ?? null) === $sha) {
                return true;
            }
            $st = $this->db()->prepare(
                'insert into linked_account_sessions (provider, user_id, archive, sha, updated_at) values (?, ?, ?, ?, now()) ' .
                'on conflict (provider, user_id) do update set archive = excluded.archive, sha = excluded.sha, updated_at = now()'
            );
            $st->execute([$this->provider, $userId, base64_encode($raw), $sha]);
            $this->saved[$key] = $sha;
            return true;
        } catch (\Throwable $e) {
            error_log('[sessions] save failed: ' . $e->getMessage());
            return false;
        }
    }

    public function delete(string $userId): void
    {
        if (!$this->enabled()) {
            return;
        }
        try {
            $st = $this->db()->prepare('delete from linked_account_sessions where provider = ? and user_id = ?');
            $st->execute([$this->provider, $userId]);
            unset($this->saved[$this->provider . ':' . $userId]);
        } catch (\Throwable $e) {
            error_log('[sessions] delete failed: ' . $e->getMessage());
        }
    }
}
