type LogLevel = 'debug' | 'info' | 'warn' | 'error';

const LEVELS: Record<LogLevel, number> = {
  debug: 0,
  info: 1,
  warn: 2,
  error: 3,
};

function resolveLogLevel(): LogLevel {
  const raw = process.env['LOG_LEVEL']?.toLowerCase();
  if (raw && raw in LEVELS) {
    return raw as LogLevel;
  }
  if (raw) {
    // Cannot use logger here (circular), fall back to stderr write once.
    process.stderr.write(`[logger] Invalid LOG_LEVEL "${raw}", falling back to "info"\n`);
  }
  return 'info';
}

const currentLevel: LogLevel = resolveLogLevel();

function maskSecrets(message: string): string {
  // Mask SNYK_TOKEN and GITHUB_TOKEN patterns
  return message
    .replace(/token\s+[a-zA-Z0-9_-]{10,}/gi, 'token ***')
    .replace(/Bearer\s+[a-zA-Z0-9_.-]{10,}/gi, '******')
    .replace(/ghp_[a-zA-Z0-9]{36}/g, 'ghp_***')
    .replace(/snyk_[a-zA-Z0-9]{32,}/gi, 'snyk_***');
}

function safeStringify(value: unknown): string {
  const seen = new WeakSet<object>();
  try {
    return (
      JSON.stringify(value, (_key, val: unknown) => {
        if (typeof val === 'bigint') return val.toString();
        if (typeof val === 'function') return `[Function ${val.name || 'anonymous'}]`;
        if (val instanceof Error) {
          return { name: val.name, message: val.message, stack: val.stack };
        }
        if (typeof val === 'object' && val !== null) {
          if (seen.has(val)) return '[Circular]';
          seen.add(val);
        }
        return val;
      }) ?? String(value)
    );
  } catch {
    try {
      return String(value);
    } catch {
      return '[Unserializable]';
    }
  }
}

function log(level: LogLevel, message: string, ...args: unknown[]): void {
  if (LEVELS[level] < LEVELS[currentLevel]) return;

  const timestamp = new Date().toISOString();
  const safeMessage = maskSecrets(message);
  const prefix = `[${timestamp}] [${level.toUpperCase()}]`;

  const formattedArgs = args.map((a) => maskSecrets(typeof a === 'string' ? a : safeStringify(a)));

  const output = [prefix, safeMessage, ...formattedArgs].join(' ');

  if (level === 'error' || level === 'warn') {
    process.stderr.write(output + '\n');
  } else {
    process.stdout.write(output + '\n');
  }
}

export const logger = {
  debug: (msg: string, ...args: unknown[]): void => log('debug', msg, ...args),
  info: (msg: string, ...args: unknown[]): void => log('info', msg, ...args),
  warn: (msg: string, ...args: unknown[]): void => log('warn', msg, ...args),
  error: (msg: string, ...args: unknown[]): void => log('error', msg, ...args),
};
