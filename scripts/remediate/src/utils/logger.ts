type LogLevel = 'debug' | 'info' | 'warn' | 'error';

const LEVELS: Record<LogLevel, number> = {
  debug: 0,
  info: 1,
  warn: 2,
  error: 3,
};

const currentLevel: LogLevel =
  (process.env['LOG_LEVEL'] as LogLevel | undefined) ?? 'info';

function maskSecrets(message: string): string {
  // Mask SNYK_TOKEN and GITHUB_TOKEN patterns
  return message
    .replace(/token\s+[a-zA-Z0-9_\-]{10,}/gi, 'token ***')
    .replace(/Bearer\s+[a-zA-Z0-9_\-\.]{10,}/gi, '******')
    .replace(/ghp_[a-zA-Z0-9]{36}/g, 'ghp_***')
    .replace(/snyk_[a-zA-Z0-9]{32,}/gi, 'snyk_***');
}

function log(level: LogLevel, message: string, ...args: unknown[]): void {
  if (LEVELS[level] < LEVELS[currentLevel]) return;

  const timestamp = new Date().toISOString();
  const safeMessage = maskSecrets(message);
  const prefix = `[${timestamp}] [${level.toUpperCase()}]`;

  const formattedArgs = args.map((a) =>
    typeof a === 'string' ? maskSecrets(a) : JSON.stringify(a),
  );

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
