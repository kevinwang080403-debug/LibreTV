#!/usr/bin/env node
/**
 * Build-time injector: 把 Cloudflare Build variables（process.env.PASSWORD 等）
 * 写入 wrangler.jsonc 的 vars 字段。
 *
 * 为什么要这样做？
 * Cloudflare Workers 的 Secret 存在 Dashboard，但 `wrangler deploy` 以 wrangler.jsonc
 * 为真相源，会清空所有 Dashboard 里的 vars/secrets。只有 wrangler.jsonc 里显式声明
 * 的变量会被绑定到 Worker 运行时。
 *
 * 把密码写进 git 里不安全，所以：
 *   - wrangler.jsonc 里不含密码（版本控制安全）
 *   - 构建时从环境变量读密码，写入 wrangler.jsonc（只在构建环境临时存在）
 *   - 构建后 wrangler deploy 时该文件已包含密码
 */

const fs = require('fs');
const path = require('path');

const wranglerPath = path.join(__dirname, '..', 'wrangler.jsonc');
if (!fs.existsSync(wranglerPath)) {
  console.log('[inject] wrangler.jsonc 不存在，跳过');
  process.exit(0);
}

const raw = fs.readFileSync(wranglerPath, 'utf8');
// 简易 JSONC 支持：去掉行注释与块注释
const stripped = raw
  .replace(/\/\*[\s\S]*?\*\//g, '')
  .replace(/(^|[^:])\/\/[^\n]*/g, '$1');

let config;
try {
  config = JSON.parse(stripped);
} catch (err) {
  console.error('[inject] 解析 wrangler.jsonc 失败:', err.message);
  process.exit(1);
}

config.vars = config.vars || {};

const keysToInject = ['PASSWORD', 'PROXY_SECRET'];
let injected = 0;
for (const key of keysToInject) {
  const val = process.env[key];
  if (val && val.length > 0) {
    config.vars[key] = val;
    console.log(`[inject] 已注入 ${key}（长度 ${val.length}）`);
    injected += 1;
  } else {
    console.log(`[inject] 跳过 ${key}（环境变量未设置）`);
  }
}

fs.writeFileSync(wranglerPath, JSON.stringify(config, null, 2));
console.log(`[inject] 完成，共注入 ${injected} 个变量到 wrangler.jsonc`);
