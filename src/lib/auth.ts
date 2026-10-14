/**
 * 会话鉴权：httpOnly cookie + HMAC 签名。
 * Edge Runtime 兼容版：使用 Web Crypto API（crypto.subtle），所有加密操作异步化。
 */

import { getCloudflareContext } from '@opennextjs/cloudflare';

export const SESSION_COOKIE = 'ltv_session';
const SESSION_TTL_MS = 90 * 24 * 60 * 60 * 1000; // 90 天

const encoder = new TextEncoder();

function cfEnv(key: string): string | undefined {
  try {
    const env = getCloudflareContext().env as Record<string, string | undefined>;
    if (env && env[key]) return env[key];
  } catch {
    // getCloudflareContext 不可用（非 Workers 环境），回退到 process.env
  }
  return process.env[key];
}

export function getPassword(): string {
  return cfEnv('PASSWORD') || '';
}

export function isPasswordConfigured(): boolean {
  return getPassword().length > 0;
}

function bytesToHex(bytes: Uint8Array): string {
  let hex = '';
  for (let i = 0; i < bytes.length; i++) hex += bytes[i].toString(16).padStart(2, '0');
  return hex;
}

async function sha256Hex(input: string): Promise<string> {
  const digest = await crypto.subtle.digest('SHA-256', encoder.encode(input));
  return bytesToHex(new Uint8Array(digest));
}

async function sha256Bytes(input: string): Promise<Uint8Array> {
  const digest = await crypto.subtle.digest('SHA-256', encoder.encode(input));
  return new Uint8Array(digest);
}

async function getSecret(): Promise<string> {
  const secret = cfEnv('PROXY_SECRET');
  if (secret) return secret;
  return sha256Hex(getPassword() + ':libretv::session-salt');
}

async function hmac(payload: string): Promise<string> {
  const secret = await getSecret();
  const key = await crypto.subtle.importKey(
    'raw',
    encoder.encode(secret),
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign']
  );
  const sig = await crypto.subtle.sign('HMAC', key, encoder.encode(payload));
  return bytesToHex(new Uint8Array(sig));
}

/** 恒定时间字符串比较（防时序攻击） */
function timingSafeEqualStr(a: string, b: string): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return diff === 0;
}

/** 恒定时间字节比较 */
function timingSafeEqualBytes(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a[i] ^ b[i];
  return diff === 0;
}

/** 生成签名会话 token：`<expiresAtMs>.<hmac>` */
export async function signSession(): Promise<{ token: string; expiresAt: number }> {
  const expiresAt = Date.now() + SESSION_TTL_MS;
  const payload = String(expiresAt);
  const sig = await hmac(payload);
  return { token: `${payload}.${sig}`, expiresAt };
}

/** 校验会话 token 的签名与有效期 */
export async function verifySession(token: string | undefined | null): Promise<boolean> {
  if (!token) return false;
  const dot = token.lastIndexOf('.');
  if (dot <= 0) return false;
  const payload = token.slice(0, dot);
  const sig = token.slice(dot + 1);
  const expected = await hmac(payload);
  if (!timingSafeEqualStr(sig, expected)) return false;
  const expiresAt = parseInt(payload, 10);
  if (!Number.isFinite(expiresAt)) return false;
  return Date.now() < expiresAt;
}

/** 恒定时间比较密码（比较 sha256 摘要避免长度泄漏） */
export async function checkPassword(input: string): Promise<boolean> {
  const password = getPassword();
  if (!password) return false;
  const a = await sha256Bytes(input);
  const b = await sha256Bytes(password);
  return timingSafeEqualBytes(a, b);
}

/** 从请求 Cookie 中解析会话 */
export async function sessionFromCookieHeader(cookieHeader: string | null): Promise<boolean> {
  if (!cookieHeader) return false;
  const cookies = cookieHeader.split(';');
  for (const c of cookies) {
    const eq = c.indexOf('=');
    if (eq === -1) continue;
    const name = c.slice(0, eq).trim();
    if (name === SESSION_COOKIE) {
      return verifySession(decodeURIComponent(c.slice(eq + 1).trim()));
    }
  }
  return false;
}

// —— 登录速率限制（内存实现，单实例部署足够；多实例可换 Redis） ——

const attemptMap = new Map<string, { count: number; resetAt: number }>();
const MAX_ATTEMPTS = 10;
const WINDOW_MS = 10 * 60 * 1000;

export function checkRateLimit(ip: string): boolean {
  const now = Date.now();
  const entry = attemptMap.get(ip);
  if (!entry || now > entry.resetAt) {
    attemptMap.set(ip, { count: 1, resetAt: now + WINDOW_MS });
    return true;
  }
  if (entry.count >= MAX_ATTEMPTS) return false;
  entry.count += 1;
  return true;
}

export function clearRateLimit(ip: string): void {
  attemptMap.delete(ip);
}
