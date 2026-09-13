#!/usr/bin/env node
/**

 */

'use strict';

const { exec, spawn } = require('child_process');
const fs = require('fs');
const os = require('os');
const path = require('path');
const http = require('http');
const https = require('https');
const crypto = require('crypto');

/* ============================================================================
 * 一、用户配置区 —— 所有可修改项集中在此（修改一处全生效）
 * ========================================================================== */
const ENV = process.env;

const CONFIG = {
  /** 节点名称前缀 */
  name: ENV.NAME || 'sing-box',

  /** 全协议共用 UUID（不填则每次启动随机生成，可用 UUID 环境变量固定） */
  uuid: ENV.UUID || '',

  /** 探活 HTTP 服务端口 */
  webPort: Number(ENV.PORT || ENV.WEB_PORT || 3000),

  /** Reality 握手 SNI（已提取为变量，直接改这里即可） */
  realitySni: ENV.REALITY_SNI || 'www.yahoo.com',

  /** vmess / trojan 共用 WS 路径 */
  wsPath: ENV.XPATH || '/wo',

  /**
   * 直连节点地址（仅 vless-reality / hysteria2 / tuic 使用，须填服务器公网 IP 或解析到服务器的域名）
   * 注意：与 ARGO_DOMAIN 无关 —— vmess/trojan 走 Cloudflare 隧道，地址固定用 ARGO_DOMAIN
   * 留空则自动获取公网 IP
   */
  host: ENV.HOST || '',

  /** komari 监控（替代 NEZHA）：面板地址 + 节点 Token */
  komariEndpoint: ENV.KOMARI_ENDPOINT || ENV.KOMARI_SERVER || '',
  komariToken: ENV.KOMARI_TOKEN || '',
  komariAgentUrl: ENV.KOMARI_AGENT_URL || '',

  /** Cloudflare Argo 隧道 */
  argoDomain: ENV.ARGO_DOMAIN || '',
  argoAuth: ENV.ARGO_AUTH || '',

  /** 组件开关（hy2 / tuic 均为 UDP，PaaS 平台一般只能暴露一个；hy2 默认关闭，设 ENABLE_HY2=true 开启） */
  enableHysteria2: (ENV.ENABLE_HY2 || '').toLowerCase() === 'true',
  enableTuic: (ENV.ENABLE_TUIC || 'true').toLowerCase() !== 'false',

  /** 下载配置 */
  singBoxVersion: ENV.SING_BOX_VERSION || '1.11.3',
  ghProxy: ENV.GH_PROXY || '',
};

/* ---- Telegram 推送配置 ---- */
const CHAT_ID = process.env.CHAT_ID || '';                  // Telegram chat_id  两个变量不全不推送节点到TG
const BOT_TOKEN = process.env.BOT_TOKEN || '';              // Telegram bot_token 两个变量不全不推送节点到TG

/* ---- Argo 隧道本地端口 ---- */
const ARGO_PORT = process.env.ARGO_PORT || 8011;            // Argo 隧道本地端口：vmess 用，trojan 用 ARGO_PORT+1

/* ============================================================================
 * 二、协议公共配置 —— 各协议相同项统一前置（修改一处全生效）
 *     协议块内只书写自身差异项，公共项全部引用此处
 * ========================================================================== */
const SHARED = {
  /** 所有协议共用同一 UUID */
  get uuid() {
    return CONFIG.uuid;
  },

  /** Reality / Hysteria2 / TUIC 共用 SNI */
  get sni() {
    return CONFIG.realitySni;
  },

  /** uTLS 指纹 */
  fingerprint: 'chrome',

  /** vless flow */
  flow: 'xtls-rprx-vision',

  /** vmess / trojan 共用 WS 传输 */
  ws: {
    type: 'ws',
    path: CONFIG.wsPath,
  },

  /** 本地监听地址（vmess / trojan 经 Argo 隧道，仅本机访问） */
  listenLocal: '127.0.0.1',

  /** 直连监听地址（vless / hysteria2 / tuic 共用） */
  listenAll: '::',

  /** hysteria2 / tuic 共用 ALPN */
  alpn: ['h3'],
};

/* ============================================================================
 * 三、运行时状态与通用工具函数
 * ========================================================================== */
const BIN_DIR = path.join(__dirname, 'bin');
const SB_CONFIG_FILE = path.join(__dirname, 'config.json');
const NODES_FILE = path.join(__dirname, 'nodes.txt');

/** 本脚本拉起的子进程，退出时统一清理（避免残留重复进程） */
const children = [];
let shuttingDown = false;

/** 统一日志格式 */
function log(tag, msg) {
  console.log(`[${new Date().toISOString()}] [${tag}] ${msg}`);
}

/** 将命令包装为 Promise */
function run(cmd) {
  return new Promise((resolve, reject) => {
    exec(cmd, (err, stdout, stderr) => {
      if (err) reject(new Error(`${cmd} 执行失败: ${stderr || err.message}`));
      else resolve(stdout);
    });
  });
}

/** 下载文件（自动跟随重定向） */
function downloadFile(url, dest, redirects = 5) {
  return new Promise((resolve, reject) => {
    const client = url.startsWith('https:') ? https : http;
    const req = client.get(url, (res) => {
      // 跟随重定向
      if (res.statusCode >= 300 && res.statusCode < 400 && res.headers.location) {
        res.resume();
        if (redirects <= 0) return reject(new Error(`重定向次数过多: ${url}`));
        return resolve(downloadFile(new URL(res.headers.location, url).href, dest, redirects - 1));
      }
      if (res.statusCode !== 200) {
        res.resume();
        return reject(new Error(`下载失败 HTTP ${res.statusCode}: ${url}`));
      }
      const file = fs.createWriteStream(dest);
      res.pipe(file);
      file.on('finish', () => file.close(() => resolve(dest)));
      file.on('error', (err) => {
        file.close();
        fs.unlink(dest, () => reject(err));
      });
    });
    req.on('error', reject);
  });
}

/** 拼接下载地址（自动套用 GitHub 加速前缀） */
function ghUrl(url) {
  return CONFIG.ghProxy ? CONFIG.ghProxy.replace(/\/?$/, '/') + url : url;
}

/** 获取当前系统对应的架构名 */
function getArch() {
  switch (os.arch()) {
    case 'x64':
      return 'amd64';
    case 'arm64':
      return 'arm64';
    default:
      throw new Error(`不支持的架构: ${os.arch()}`);
  }
}

/** 获取 UUID：优先使用环境变量，否则每次启动随机生成 */
function resolveUuid() {
  if (!CONFIG.uuid) CONFIG.uuid = crypto.randomUUID();
  return CONFIG.uuid;
}

/** 获取公网 IP（失败返回 null，不阻塞流程） */
function fetchPublicIp() {
  return new Promise((resolve) => {
    const req = https.get('https://api.ipify.org', { timeout: 3000 }, (res) => {
      let data = '';
      res.on('data', (chunk) => (data += chunk));
      res.on('end', () => resolve(data.trim() || null));
    });
    req.on('timeout', () => {
      req.destroy();
      resolve(null);
    });
    req.on('error', () => resolve(null));
  });
}

/* ============================================================================
 * 四、sing-box 配置生成
 * ========================================================================== */

/**
 * 生成 sing-box 配置
 * 各协议块仅书写自身差异项（端口 / flow / reality 密钥等），
 * UUID、SNI、指纹、WS 传输等公共项全部引用 SHARED。
 */
function buildSingBoxConfig({ privateKey, shortId, tlsCert }) {
  /** hysteria2 / tuic 共用的服务端 TLS（自签证书） */
  const SERVER_TLS =
    tlsCert && {
      enabled: true,
      certificate_path: tlsCert.cert,
      key_path: tlsCert.key,
    };

  const inbounds = [
    /* ---- vmess + ws（经 Argo 隧道，本地明文监听） ---- */
    {
      type: 'vmess',
      tag: 'vmess-ws',
      listen: SHARED.listenLocal,
      listen_port: Number(ARGO_PORT),
      users: [{ uuid: SHARED.uuid, alter_id: 0 }],
      transport: { ...SHARED.ws },
    },

    /* ---- trojan + ws（经 Argo 隧道，本地明文监听） ---- */
    {
      type: 'trojan',
      tag: 'trojan-ws',
      listen: SHARED.listenLocal,
      listen_port: Number(ARGO_PORT) + 1, // trojan 本地端口 = ARGO_PORT + 1（同一端口不能被两个入站绑定）
      users: [{ password: SHARED.uuid }],
      transport: { ...SHARED.ws },
    },

    /* ---- vless + reality（直连） ---- */
    {
      type: 'vless',
      tag: 'vless-reality',
      listen: SHARED.listenAll,
      listen_port: 443,
      users: [{ uuid: SHARED.uuid, flow: SHARED.flow }],
      tls: {
        enabled: true,
        server_name: SHARED.sni,
        utls: { enabled: true, fingerprint: SHARED.fingerprint },
        reality: {
          enabled: true,
          handshake: { server: SHARED.sni, server_port: 443 },
          private_key: privateKey,
          short_id: [shortId],
        },
      },
    },
  ];

  /* ---- hysteria2（UDP，可选） ---- */
  if (SERVER_TLS && CONFIG.enableHysteria2) {
    inbounds.push({
      type: 'hysteria2',
      tag: 'hysteria2',
      listen: SHARED.listenAll,
      listen_port: 10002,
      users: [{ password: SHARED.uuid }],
      tls: { ...SERVER_TLS, alpn: SHARED.alpn },
    });
  }

  /* ---- tuic（UDP，可选） ---- */
  if (SERVER_TLS && CONFIG.enableTuic) {
    inbounds.push({
      type: 'tuic',
      tag: 'tuic',
      listen: SHARED.listenAll,
      listen_port: 10003,
      users: [{ uuid: SHARED.uuid, password: SHARED.uuid }],
      congestion_control: 'bbr',
      udp_relay_mode: 'native',
      tls: { ...SERVER_TLS, alpn: SHARED.alpn },
    });
  }

  return {
    log: { level: 'warning', timestamp: true },
    inbounds,
    outbounds: [{ type: 'direct', tag: 'direct' }],
  };
}

/* ============================================================================
 * 五、组件安装与启动
 * ========================================================================== */

/** 下载 sing-box 二进制并解压 */
async function downloadSingBox() {
  const arch = getArch();
  const ver = CONFIG.singBoxVersion;
  const url = ghUrl(
    `https://github.com/SagerNet/sing-box/releases/download/v${ver}/sing-box-${ver}-linux-${arch}.tar.gz`
  );
  const tgz = path.join(BIN_DIR, 'sing-box.tar.gz');
  const bin = path.join(BIN_DIR, 'sing-box');

  if (!fs.existsSync(bin)) {
    log('sing-box', `下载 v${ver} (${arch}) ...`);
    await downloadFile(url, tgz);
    await run(`tar -xzf "${tgz}" -C "${BIN_DIR}"`);
    fs.renameSync(path.join(BIN_DIR, `sing-box-${ver}-linux-${arch}`, 'sing-box'), bin);
    fs.rmSync(tgz, { force: true });
    fs.rmSync(path.join(BIN_DIR, `sing-box-${ver}-linux-${arch}`), { recursive: true, force: true });
    fs.chmodSync(bin, 0o755);
  }
  return bin;
}

/** 生成 Reality 密钥对 */
async function generateRealityKeys(sbBin) {
  const out = await run(`"${sbBin}" generate reality-keypair`);
  const privateKey = (out.match(/PrivateKey:\s*(\S+)/) || [])[1];
  const publicKey = (out.match(/PublicKey:\s*(\S+)/) || [])[1];
  if (!privateKey || !publicKey) throw new Error('Reality 密钥对生成失败');
  return { privateKey, publicKey };
}

/** 生成 hysteria2 / tuic 共用的自签证书（openssl 不可用时返回 null） */
async function generateTlsCert() {
  const cert = path.join(BIN_DIR, 'cert.pem');
  const key = path.join(BIN_DIR, 'key.pem');
  try {
    await run(
      `openssl req -x509 -newkey rsa:2048 -sha256 -days 3650 -nodes ` +
        `-keyout "${key}" -out "${cert}" -subj "/CN=${SHARED.sni}"`
    );
    return { cert, key };
  } catch (err) {
    log('tls', `openssl 不可用，已跳过 hysteria2 / tuic: ${err.message}`);
    return null;
  }
}

/** 启动 sing-box 主进程 */
function startSingBox(sbBin) {
  log('sing-box', '启动 sing-box ...');
  const child = spawn(sbBin, ['run', '-c', SB_CONFIG_FILE], { stdio: 'inherit' });
  children.push(child);
  child.on('exit', (code) => {
    if (shuttingDown) return;
    log('sing-box', `进程异常退出（代码 ${code}），脚本即将退出以便容器重启`);
    process.exit(code || 1);
  });
}

/**
 * 安装并启动 komari 监控端（替代旧版 NEZHA）
 * 等价于: nohup ./komari-agent -e <endpoint> -t <token> &
 * 进程由本脚本统一管理，避免重启后残留重复 agent
 */
async function setupKomari() {
  if (!CONFIG.komariEndpoint || !CONFIG.komariToken) {
    log('komari', '未配置 KOMARI_ENDPOINT / KOMARI_TOKEN，跳过监控端');
    return;
  }
  const bin = path.join(BIN_DIR, 'komari-agent');
  if (!fs.existsSync(bin)) {
    const url =
      CONFIG.komariAgentUrl ||
      ghUrl(
        `https://github.com/komari-monitor/komari-agent/releases/download/1.2.60/komari-agent-linux-${getArch()}`
      );
    log('komari', '下载 komari-agent ...');
    await downloadFile(url, bin);
    fs.chmodSync(bin, 0o755);
  }
  const child = spawn(bin, ['-e', CONFIG.komariEndpoint, '-t', CONFIG.komariToken], {
    stdio: 'ignore',
  });
  children.push(child);
  log('komari', `监控端已启动 → ${CONFIG.komariEndpoint}`);
}

/** 安装并启动 Cloudflare Argo 隧道（vmess / trojan 的对外入口） */
async function setupArgo() {
  if (!CONFIG.argoDomain || !CONFIG.argoAuth) {
    log('argo', '未配置 ARGO_DOMAIN / ARGO_AUTH，跳过 Argo 隧道');
    return;
  }
  const bin = path.join(BIN_DIR, 'cloudflared');
  if (!fs.existsSync(bin)) {
    const url = ghUrl(
      `https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-linux-${getArch()}`
    );
    log('argo', '下载 cloudflared ...');
    await downloadFile(url, bin);
    fs.chmodSync(bin, 0o755);
  }

  let args;
  if (CONFIG.argoAuth.trim().startsWith('{')) {
    // JSON 凭证方式
    const jsonPath = path.join(BIN_DIR, 'tunnel.json');
    fs.writeFileSync(jsonPath, CONFIG.argoAuth);
    const tunnelId = String(JSON.parse(CONFIG.argoAuth).TunnelID || '');
    args = ['tunnel', '--no-autoupdate', '--config', jsonPath, 'run', tunnelId];
  } else {
    // Token 方式
    args = ['tunnel', '--no-autoupdate', 'run', '--token', CONFIG.argoAuth];
  }

  const child = spawn(bin, args, { stdio: 'ignore' });
  children.push(child);
  log('argo', `隧道已启动 → ${CONFIG.argoDomain}`);
}

/** 启动探活 HTTP 服务（保持容器存活 / 健康检查） */
function startWebServer() {
  const server = http.createServer((req, res) => {
    res.writeHead(200, { 'Content-Type': 'text/plain; charset=utf-8' });
    res.end('Hello, world! sing-box is running.\n');
  });
  server.listen(CONFIG.webPort, () =>
    log('web', `探活服务已启动: http://0.0.0.0:${CONFIG.webPort}`)
  );
  return server;
}

/* ============================================================================
 * 六、节点信息输出
 * ========================================================================== */
function printNodeLinks({ publicKey, shortId, hasUdp }) {
  const host = CONFIG.host || '127.0.0.1';
  const name = CONFIG.name;
  const links = [];

  /* vless + reality（直连） */
  links.push(
    `vless://${SHARED.uuid}@${host}:443?` +
      `encryption=none&security=reality&sni=${SHARED.sni}&fp=${SHARED.fingerprint}` +
      `&pbk=${publicKey}&sid=${shortId}&type=tcp&flow=${SHARED.flow}#${name}-reality`
  );

  /* vmess / trojan（依赖 Argo 隧道） */
  if (CONFIG.argoDomain) {
    const vmessJson = {
      v: '2',
      ps: `${name}-vmess`,
      add: CONFIG.argoDomain,
      port: '443',
      id: SHARED.uuid,
      aid: '0',
      scy: 'auto',
      net: 'ws',
      type: 'none',
      host: CONFIG.argoDomain,
      path: SHARED.ws.path,
      tls: 'tls',
      sni: CONFIG.argoDomain,
      fp: SHARED.fingerprint,
    };
    links.push('vmess://' + Buffer.from(JSON.stringify(vmessJson)).toString('base64'));
    links.push(
      `trojan://${SHARED.uuid}@${CONFIG.argoDomain}:443?security=tls&sni=${CONFIG.argoDomain}` +
        `&fp=${SHARED.fingerprint}&type=ws&host=${CONFIG.argoDomain}` +
        `&path=${encodeURIComponent(SHARED.ws.path)}#${name}-trojan`
    );
  }

  /* hysteria2 / tuic（UDP 直连） */
  if (hasUdp) {
    links.push(
      `hysteria2://${SHARED.uuid}@${host}:10002/?sni=${SHARED.sni}&insecure=1&alpn=h3#${name}-hy2`
    );
    links.push(
      `tuic://${SHARED.uuid}:${SHARED.uuid}@${host}:10003?sni=${SHARED.sni}` +
        `&congestion_control=bbr&udp_relay_mode=native&alpn=h3&allow_insecure=1#${name}-tuic`
    );
  }

  console.log('\n========== 节点信息 ==========');
  links.forEach((link) => console.log(link + '\n'));
  console.log('==============================\n');
  return links;
}

/** 保存节点信息到 nodes.txt（与本脚本同目录，每次启动覆盖更新） */
function saveNodeLinks(links) {
  const content = [
    '========== 节点信息 ==========',
    ...links,
    '==============================',
  ].join('\n');
  fs.writeFileSync(NODES_FILE, content + '\n');
  log('save', `节点信息已保存: ${NODES_FILE}`);
}

/**
 * 推送节点信息到 Telegram
 * CHAT_ID 与 BOT_TOKEN 两个变量不全时不推送
 */
function pushToTelegram(links) {
  if (!CHAT_ID || !BOT_TOKEN) {
    log('telegram', 'CHAT_ID / BOT_TOKEN 未配置齐全，跳过 TG 推送');
    return;
  }

  // Telegram 单条消息上限 4096 字符，超长时按链接分段发送
  const chunks = [];
  let current = '';
  for (const link of links) {
    if (current && current.length + link.length + 2 > 3800) {
      chunks.push(current);
      current = link;
    } else {
      current = current ? `${current}\n\n${link}` : link;
    }
  }
  if (current) chunks.push(current);

  chunks.forEach((text, index) => {
    const title =
      chunks.length > 1
        ? `🚀 sing-box 节点信息 (${index + 1}/${chunks.length})`
        : '🚀 sing-box 节点信息';
    const payload = JSON.stringify({
      chat_id: CHAT_ID,
      text: `${title}\n\n${text}`,
      disable_web_page_preview: true,
    });
    const req = https.request(
      {
        hostname: 'api.telegram.org',
        path: `/bot${BOT_TOKEN}/sendMessage`,
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Content-Length': Buffer.byteLength(payload),
        },
        timeout: 10000,
      },
      (res) => {
        res.resume();
        if (res.statusCode === 200) {
          log('telegram', `节点信息已推送到 Telegram (${index + 1}/${chunks.length})`);
        } else {
          log('telegram', `推送失败 HTTP ${res.statusCode}`);
        }
      }
    );
    req.on('timeout', () => {
      req.destroy();
      log('telegram', '推送超时');
    });
    req.on('error', (err) => log('telegram', `推送失败: ${err.message}`));
    req.write(payload);
    req.end();
  });
}

/* ============================================================================
 * 七、主流程
 * ========================================================================== */
async function main() {
  fs.mkdirSync(BIN_DIR, { recursive: true });
  resolveUuid();
  log('init', `UUID: ${CONFIG.uuid}`);

  if (!CONFIG.host) {
    const ip = await fetchPublicIp();
    if (ip) CONFIG.host = ip;
    else log('init', '未能获取公网 IP，节点链接将使用 127.0.0.1（可用 HOST 环境变量指定）');
  }

  const sbBin = await downloadSingBox();
  const { privateKey, publicKey } = await generateRealityKeys(sbBin);
  const shortId = crypto.randomBytes(4).toString('hex');
  const tlsCert =
    CONFIG.enableHysteria2 || CONFIG.enableTuic ? await generateTlsCert() : null;

  fs.writeFileSync(
    SB_CONFIG_FILE,
    JSON.stringify(buildSingBoxConfig({ privateKey, shortId, tlsCert }), null, 2)
  );
  log('sing-box', `配置已生成: ${SB_CONFIG_FILE}`);

  startSingBox(sbBin);
  await setupKomari();
  await setupArgo();
  startWebServer();

  const links = printNodeLinks({
    publicKey,
    shortId,
    hasUdp: !!tlsCert && (CONFIG.enableHysteria2 || CONFIG.enableTuic),
  });
  saveNodeLinks(links);
  pushToTelegram(links);
}

/** 退出时统一清理子进程 */
function shutdown() {
  if (shuttingDown) return;
  shuttingDown = true;
  log('exit', '正在退出，清理子进程 ...');
  children.forEach((child) => child.kill('SIGKILL'));
  process.exit(0);
}
process.on('SIGINT', shutdown);
process.on('SIGTERM', shutdown);

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
