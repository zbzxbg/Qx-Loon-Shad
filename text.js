/**
 * 节点 IP 纯净度与欺诈度检测 (高并发重构版)
 * 融合 Quantumult X 经典沙盒套路：Promise.race 超时控制 + IIFE 并发 + finally 异常兜底
 */

const IPPURE_URL = "https://my.ippure.com/v1/info";
const IPV4_API = "http://ip-api.com/json?lang=zh-CN";
const IPAPI_IS_URL = "https://api.ipapi.is/";
const TIMEOUT_MS = 2800; // 全局单个接口超时时间 (毫秒)

// 从环境参数获取节点名 (兼容字符串或对象传参)
const nodeName = typeof $environment.params === "string" ? $environment.params : ($environment.params?.node || $environment.params || "当前节点");
const maskIP = $persistentStore.read("MaskIP") === "true";

// 掩码函数
function maskIpAddress(ip) {
  if (!maskIP || !ip) return ip;
  const parts = String(ip).split(".");
  if (parts.length === 4) return `${parts[0]}.${parts[1]}.*.*`;
  if (ip.includes(":")) {
    const v6parts = ip.split(":");
    if (v6parts.length >= 4) return `${v6parts.slice(0, 4).join(":")}:*`;
  }
  return ip;
}

// 经典的赛跑超时锁套路
function timeout(delay = TIMEOUT_MS) {
  return new Promise((_, reject) => {
    setTimeout(() => reject("Timeout"), delay);
  });
}

// 封装 QX 原生 $task.fetch 请求，并融合超时控制
function qxFetch(url, headers = {}) {
  const opts = {
    url: url,
    opts: { policy: nodeName }, // 强制走当前选中的节点
    timeout: TIMEOUT_MS,
    headers: headers
  };
  
  return Promise.race([
    $task.fetch(opts).then(resp => {
      if (!resp.body) throw new Error("empty response");
      return resp.body;
    }),
    timeout(TIMEOUT_MS)
  ]);
}

function safeJsonParse(s) {
  try { return JSON.parse(s); } catch (_) { return null; }
}

function toInt(v) {
  const n = Number(v);
  return Number.isFinite(n) ? Math.round(n) : null;
}

function severityMeta(sev) {
  if (sev >= 4) return { icon: "xmark.octagon.fill", color: "#8E0000" };
  if (sev >= 3) return { icon: "exclamationmark.triangle.fill", color: "#FF3B30" };
  if (sev >= 2) return { icon: "exclamationmark.circle.fill", color: "#FF9500" };
  if (sev >= 1) return { icon: "exclamationmark.circle", color: "#FFCC00" };
  return { icon: "checkmark.seal.fill", color: "#34C759" };
}

// --- 评分规则函数库 ---

function gradeIppure(score) {
  const s = toInt(score);
  if (s === null) return { sev: 2, text: "IPPure：获取失败" };
  if (s >= 80) return { sev: 4, text: `IPPure：🛑 极高风险 (${s})` };
  if (s >= 70) return { sev: 3, text: `IPPure：⚠️ 高风险 (${s})` };
  if (s >= 40) return { sev: 1, text: `IPPure：🔶 中等风险 (${s})` };
  return { sev: 0, text: `IPPure：✅ 低风险 (${s})` };
}

function gradeIpapi(j) {
  if (!j || !j.company) return { sev: 2, text: "ipapi：获取失败" };
  const abuserScoreText = j.company.abuser_score;
  if (!abuserScoreText || typeof abuserScoreText !== "string") return { sev: 2, text: "ipapi：无评分" };
  const m = abuserScoreText.match(/([0-9.]+)\s*\(([^)]+)\)/);
  if (!m) return { sev: 2, text: `ipapi：${abuserScoreText}` };

  const ratio = Number(m[1]);
  const level = String(m[2] || "").trim();
  const pct = Number.isFinite(ratio) ? `${Math.round(ratio * 10000) / 100}%` : "?";
  const sevByLevel = { "Very Low": 0, Low: 0, Elevated: 2, High: 3, "Very High": 4 };
  const sev = sevByLevel[level] ?? 2;
  const label = sev >= 4 ? "🛑 极高风险" : sev >= 3 ? "⚠️ 高风险" : sev >= 2 ? "🔶 较高风险" : "✅ 低风险";
  return { sev, text: `ipapi：${label} (${pct}, ${level})` };
}

function parseIp2locationIo(data) {
  if (!data) return { usageType: null, fraudScore: null, isProxy: false, proxyType: "-", threat: "-", country: null, countryCode: null, city: null, asn: null, asOrg: null };
  return {
    usageType: data.as_usage_type || null,
    fraudScore: data.fraud_score ?? null,
    isProxy: data.is_proxy || false,
    proxyType: data.proxy_type || "-",
    threat: data.threat || "-",
    country: data.country || null,
    countryCode: data.country_code || null,
    city: data.city || null,
    asn: data.asn || null,
    asOrg: data.as_org || null
  };
}

function gradeIp2locationIo(fraudScore) {
  const s = toInt(fraudScore);
  if (s === null) return { sev: -1, text: null };
  if (s >= 66) return { sev: 3, text: `IP2Location.io：⚠️ 高风险 (${s})` };
  if (s >= 33) return { sev: 1, text: `IP2Location.io：🔶 中风险 (${s})` };
  return { sev: 0, text: `IP2Location.io：✅ 低风险 (${s})` };
}

function ip2locationHostingText(usageType) {
  const source = "（来源:IP2Location）";
  if (!usageType) return `IP类型：未知（获取失败）${source}`;
  const typeMap = {
    "DCH": "🏢 数据中心/服务器", "WEB": "🏢 数据中心/服务器", "SES": "🏢 数据中心/服务器",
    "CDN": "🌐 CDN", "MOB": "📱 蜂窝移动网络", "ISP": "🏠 家庭宽带", "COM": "🏬 商业宽带",
    "EDU": "🎓 教育网络", "GOV": "🏛️ 政府网络", "MIL": "🎖️ 军用网络", "ORG": "🏢 组织机构", "RES": "🏠 住宅网络"
  };
  const parts = String(usageType).toUpperCase().split("/");
  const descriptions = [];
  for (const part of parts) {
    if (typeMap[part] && !descriptions.includes(typeMap[part])) descriptions.push(typeMap[part]);
  }
  if (descriptions.length === 0) return `IP类型：❓ ${usageType} ${source}`;
  return `IP类型：${descriptions.join(" / ")} (${usageType}) ${source}`;
}

function isRiskyUsageType(usageType) {
  if (!usageType) return false;
  const riskyTypes = ["DCH", "WEB", "SES", "COM", "CDN"];
  return String(usageType).toUpperCase().split("/").some(part => riskyTypes.includes(part));
}

function gradeDbip(html) {
  if (!html) return { sev: 2, text: "DB-IP：获取失败" };
  const m = html.match(/Estimated threat level for this IP address is\s*<span[^>]*>\s*([^<\s]+)\s*</i);
  const riskText = (m ? m[1] : "").toLowerCase();
  if (!riskText) return { sev: 2, text: "DB-IP：获取失败" };
  if (riskText === "high") return { sev: 3, text: "DB-IP：⚠️ 高风险 (high)" };
  if (riskText === "medium") return { sev: 1, text: "DB-IP：🔶 中风险 (medium)" };
  if (riskText === "low") return { sev: 0, text: "DB-IP：✅ 低风险 (low)" };
  return { sev: 2, text: `DB-IP：${riskText}` };
}

function gradeScamalytics(html) {
  if (!html) return { sev: 2, text: "Scamalytics：获取失败" };
  const m = html.match(/Fraud\s*Score[:\s]*(\d+)/i) || html.match(/class="score"[^>]*>(\d+)/i) || html.match(/"score"\s*:\s*(\d+)/i);
  if (!m) return { sev: 2, text: "Scamalytics：获取失败" };
  const s = toInt(m[1]);
  if (s === null) return { sev: 2, text: "Scamalytics：获取失败" };
  if (s >= 90) return { sev: 4, text: `Scamalytics：🛑 极高风险 (${s})` };
  if (s >= 60) return { sev: 3, text: `Scamalytics：⚠️ 高风险 (${s})` };
  if (s >= 20) return { sev: 1, text: `Scamalytics：🔶 中风险 (${s})` };
  return { sev: 0, text: `Scamalytics：✅ 低风险 (${s})` };
}

function gradeIpregistry(sec) {
  if (!sec) return { sev: 2, text: "ipregistry：获取失败" };
  const items = [];
  if (sec.is_proxy === true) items.push("Proxy");
  if (sec.is_tor === true) items.push("Tor");
  if (sec.is_vpn === true) items.push("VPN");
  if (sec.is_cloud_provider === true) items.push("Hosting");
  if (sec.is_abuser === true) items.push("Abuser");
  if (items.length === 0) return { sev: 0, text: "ipregistry：✅ 低风险（无标记）" };
  const sev = (items.includes("Tor") || items.includes("Abuser")) ? 3 : items.length >= 2 ? 2 : 1;
  const label = sev >= 3 ? "⚠️ 高风险" : sev >= 2 ? "🔶 较高风险" : "🔶 有标记";
  return { sev, text: `ipregistry：${label} (${items.join("/")})` };
}

function flagEmoji(code) {
  if (!code) return "";
  let c = String(code).toUpperCase();
  if (c === "TW") c = "CN";
  if (c.length !== 2) return "";
  return String.fromCodePoint(...c.split("").map((x) => 127397 + x.charCodeAt(0)));
}

function extractIpregistrySecurityFlag(html, fieldName) {
  const re = new RegExp(`${fieldName}</span>[\\s\\S]{0,300}?<div class="(?:positive|negative)">[\\s\\S]{0,800}?(Yes|No)</div>`, "i");
  const m = html.match(re);
  return m ? m[1].trim().toLowerCase() === "yes" : null;
}

// --- 各家 API 异步抓取封装 ---

async function fetchIpapi(ip) {
  const data = await qxFetch(`https://api.ipapi.is/?q=${encodeURIComponent(ip)}`);
  return safeJsonParse(data);
}

async function fetchDbipHtml(ip) {
  return await qxFetch(`https://db-ip.com/${encodeURIComponent(ip)}`);
}

async function fetchScamalyticsHtml(ip) {
  return await qxFetch(`https://scamalytics.com/ip/${encodeURIComponent(ip)}`);
}

async function fetchIpregistry(ip) {
  const html = await qxFetch(`https://ipregistry.co/${encodeURIComponent(ip)}`, {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
  });
  const isAbuser = extractIpregistrySecurityFlag(html, "Abuser");
  const isAttacker = extractIpregistrySecurityFlag(html, "Attacker");
  const isBogon = extractIpregistrySecurityFlag(html, "Bogon");
  const isCloudProvider = extractIpregistrySecurityFlag(html, "Cloud Provider");
  const isProxy = extractIpregistrySecurityFlag(html, "Proxy");
  const isRelay = extractIpregistrySecurityFlag(html, "Relay");
  const isTor = extractIpregistrySecurityFlag(html, "Tor");
  const isVpn = extractIpregistrySecurityFlag(html, "VPN");
  const isAnonymous = extractIpregistrySecurityFlag(html, "Anonymous");
  const isThreat = extractIpregistrySecurityFlag(html, "Threat");

  if ([isAbuser, isAttacker, isBogon, isCloudProvider, isProxy, isRelay, isTor, isVpn, isAnonymous, isThreat].every(v => v === null)) return null;
  return { is_abuser: isAbuser, is_attacker: isAttacker, is_bogon: isBogon, is_cloud_provider: isCloudProvider, is_proxy: isProxy, is_relay: isRelay, is_tor: isTor, is_vpn: isVpn, is_anonymous: isAnonymous, is_threat: isThreat };
}

async function fetchIp2locationIo(ip) {
  const html = await qxFetch(`https://www.ip2location.io/${encodeURIComponent(ip)}`);
  let usageMatch = html.match(/Usage\s*Type<\/label>\s*<p[^>]*>\s*\(([A-Z]+)\)/i) || html.match(/Usage\s*Type<\/label>\s*<p[^>]*>\s*([A-Z]+(?:\/[A-Z]+)?)\s*</i);
  const fraudMatch = html.match(/Fraud\s*Score<\/label>\s*<p[^>]*>\s*(\d+)/i);
  const proxyMatch = html.match(/>Proxy<\/label>\s*<p[^>]*>[^<]*<i[^>]*><\/i>\s*(Yes|No)/i);
  const proxyTypeMatch = html.match(/Proxy\s*Type<\/label>\s*<p[^>]*>\s*([^<]+)/i);
  const threatMatch = html.match(/>Threat<\/label>\s*<p[^>]*>\s*([^<]+)/i);
  const countryMatch = html.match(/>Country<\/label>[\s\S]{0,300}?<a[^>]*>([^(<]+)\(([A-Z]{2})\)<\/a>/i);
  const cityMatch = html.match(/>City<\/label>\s*<p[^>]*>([^<]+)<\/p>/i);
  const asnMatch = html.match(/>ASN<\/label>[\s\S]{0,300}?<a[^>]*>(\d+)<\/a>/i);
  const asOrgMatch = html.match(/>AS<\/label>[\s\S]{0,300}?<a[^>]*>([^<]+)<\/a>/i);

  return {
    as_usage_type: usageMatch ? usageMatch[1] : null,
    fraud_score: fraudMatch ? toInt(fraudMatch[1]) : null,
    is_proxy: proxyMatch ? proxyMatch[1].toLowerCase() === "yes" : false,
    proxy_type: proxyTypeMatch ? proxyTypeMatch[1].trim() : "-",
    threat: threatMatch ? threatMatch[1].trim() : "-",
    country: countryMatch ? countryMatch[1].trim() : null,
    country_code: countryMatch ? countryMatch[2].trim() : null,
    city: cityMatch ? cityMatch[1].trim() : null,
    asn: asnMatch ? asnMatch[1].trim() : null,
    as_org: asOrgMatch ? asOrgMatch[1].trim() : null
  };
}

async function fetchIpinfoIo(ip) {
  const html = await qxFetch(`https://ipinfo.io/${encodeURIComponent(ip)}`, {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
    "Accept": "text/html"
  });
  const detected = [];
  ["VPN", "Proxy", "Tor", "Relay", "Hosting", "Residential Proxy"].forEach(type => {
    if (new RegExp(`aria-label="${type}\\s+Detected"`, "i").test(html)) detected.push(type);
  });
  const asnTypeMatch = html.match(/>ASN type<\/span>\s*<\/td>\s*<td>([^<]+)</i);
  return { detected, asnType: asnTypeMatch ? asnTypeMatch[1].trim() : null };
}

// ========== 主并发逻辑 (IIFE 架构 + 赛跑机制) ==========

;(async () => {
  let ip = null;
  let cachedIpapiResponse = null;

  // 1. 快速获取 IP (带超时保护)
  try {
    const ipv4Data = await qxFetch(IPV4_API);
    const ipv4Json = safeJsonParse(ipv4Data);
    ip = ipv4Json?.query || ipv4Json?.ip || String(ipv4Data || "").trim();
  } catch (_) { }

  if (!ip) {
    try {
      const data = await qxFetch(IPAPI_IS_URL);
      cachedIpapiResponse = safeJsonParse(data);
      if (cachedIpapiResponse?.ip) ip = cachedIpapiResponse.ip;
    } catch (_) { }
  }

  if (!ip) {
    return $done({ title: "IP 纯净度", htmlMessage: "<p style='text-align:center;'>❌ 获取 IPv4 失败，请检查节点网络</p>", icon: "exclamationmark.triangle.fill" });
  }

  // 2. 并发拉取各大数据库 (Promise.allSettled + 赛跑)
  let ippureFraudScore = null;
  const ippureTask = qxFetch(IPPURE_URL).then(data => {
    const base = safeJsonParse(data);
    if (base) ippureFraudScore = base.fraudScore;
  }).catch(() => null);

  const tasks = {
    ipapi: cachedIpapiResponse ? Promise.resolve(cachedIpapiResponse) : fetchIpapi(ip).catch(() => null),
    ip2locIo: fetchIp2locationIo(ip).catch(() => null),
    ipinfoIo: fetchIpinfoIo(ip).catch(() => null),
    dbipHtml: fetchDbipHtml(ip).catch(() => null),
    scamHtml: fetchScamalyticsHtml(ip).catch(() => null),
    ipregistry: fetchIpregistry(ip).catch(() => null),
  };

  // 等待所有的检测任务在 TIMEOUT_MS 内完成或超时结束
  await Promise.allSettled([ippureTask, ...Object.values(tasks)]);

  // 解析成功的数据
  const ok = {};
  for (const [k, promise] of Object.entries(tasks)) {
    ok[k] = await promise;
  }

  // 3. 数据整合与展示计算
  const ipapiData = ok.ipapi || {};
  const ip2loc = parseIp2locationIo(ok.ip2locIo);
  const hostingLine = ip2locationHostingText(ip2loc.usageType);

  const ipapiHasLocation = !!(ipapiData.location?.country_code || ipapiData.location?.country);
  const ipapiHasAsn = !!ipapiData.asn?.asn;

  let countryCode = "", country = "", city = "";
  if (ipapiHasLocation) {
    countryCode = ipapiData.location?.country_code || "";
    country = ipapiData.location?.country || "";
    city = ipapiData.location?.city || "";
  } else if (ip2loc.country || ip2loc.city) {
    countryCode = ip2loc.countryCode || "";
    country = ip2loc.country || "";
    city = ip2loc.city || "";
  }
  const flag = flagEmoji(countryCode);

  let asnText = "-";
  if (ipapiHasAsn) {
    asnText = `AS${ipapiData.asn.asn} ${ipapiData.asn.org || ""}`.trim();
  } else if (ip2loc.asn) {
    asnText = `AS${ip2loc.asn} ${ip2loc.asOrg || ""}`.trim();
  }

  const grades = [
    gradeIppure(ippureFraudScore),
    gradeIpapi(ok.ipapi)
  ];
  const ip2locGrade = gradeIp2locationIo(ip2loc.fraudScore);
  if (ip2locGrade.text) grades.push(ip2locGrade);
  grades.push(gradeScamalytics(ok.scamHtml));
  grades.push(gradeDbip(ok.dbipHtml));
  grades.push(gradeIpregistry(ok.ipregistry));

  const maxSev = grades.reduce((m, g) => Math.max(m, g.sev ?? 2), 0);
  const meta = severityMeta(maxSev);

  const factorParts = [];
  const ip2locProxyItems = [];
  if (ip2loc.isProxy) ip2locProxyItems.push("Proxy");
  if (ip2loc.proxyType && ip2loc.proxyType !== "-") {
    const typeMap = { "VPN": "VPN", "TOR": "Tor", "DCH": "数据中心代理", "PUB": "公共代理", "WEB": "Web代理", "RES": "住宅代理" };
    ip2locProxyItems.push(typeMap[ip2loc.proxyType.toUpperCase()] || ip2loc.proxyType);
  }
  if (ip2loc.threat && ip2loc.threat !== "-") ip2locProxyItems.push(`威胁:${ip2loc.threat}`);
  if (ip2locProxyItems.length) factorParts.push(`IP2Location 检测类型：${ip2locProxyItems.join("/")}`);

  if (ok.ipapi) {
    const items = [];
    if (ok.ipapi.is_proxy === true) items.push("Proxy");
    if (ok.ipapi.is_tor === true) items.push("Tor");
    if (ok.ipapi.is_vpn === true) items.push("VPN");
    if (ok.ipapi.is_datacenter === true) items.push("Datacenter");
    if (ok.ipapi.is_abuser === true) items.push("Abuser");
    if (ok.ipapi.is_crawler === true) items.push("Crawler");
    if (items.length) factorParts.push(`ipapi 检测类型：${items.join("/")}`);
  }

  if (ok.ipinfoIo?.detected?.length) factorParts.push(`ipinfo.io 检测类型：${ok.ipinfoIo.detected.join("/")}`);

  if (ok.ipregistry) {
    const sec = ok.ipregistry;
    const items = [];
    if (sec.is_proxy === true) items.push("Proxy");
    if (sec.is_tor === true) items.push("Tor");
    if (sec.is_relay === true) items.push("Relay");
    if (sec.is_vpn === true) items.push("VPN");
    if (sec.is_anonymous === true) items.push("Anonymous");
    if (sec.is_cloud_provider === true) items.push("Hosting");
    if (sec.is_abuser === true) items.push("Abuser");
    if (sec.is_attacker === true) items.push("Attacker");
    if (sec.is_bogon === true) items.push("Bogon");
    if (sec.is_threat === true) items.push("Threat");
    if (items.length) factorParts.push(`ipregistry 检测类型：${items.join("/")}`);
  }

  if (ip2locProxyItems.length === 0 && ip2loc.usageType && isRiskyUsageType(ip2loc.usageType)) {
    const usageDesc = { "DCH": "数据中心", "WEB": "Web托管", "SES": "搜索引擎", "COM": "商业宽带", "CDN": "CDN" };
    const usage = String(ip2loc.usageType).toUpperCase();
    factorParts.push(`IP2Location 检测类型：${usageDesc[usage] || usage} (${ip2loc.usageType})`);
  }
  const riskLines = grades.map((g) => g.text).filter(Boolean);

  // 4. 构建 HTML 输出
  let html = `<p style="text-align: center; font-family: -apple-system; font-size: large; font-weight: thin">`;
  html += `<b><font color=#6959CD>IP</font> : </b><font color=>${maskIpAddress(ip)}</font></br>`;
  html += `<b><font color=#6959CD>ASN</font> : </b><font color=>${asnText}</font></br>`;
  html += `<b><font color=#6959CD>位置</font> : </b><font color=>${flag} ${country} ${city}</font></br>`;
  html += `<b><font color=#6959CD>类型</font> : </b><font color=>${hostingLine.replace("IP类型：", "")}</font></br>`;

  html += `</br><b><font color=#FF6347>—— 多源评分 ——</font></b></br>`;
  for (const line of riskLines) {
    const [name, ...rest] = line.split("：");
    html += `<b>${name}</b>：${rest.join("：")}</br>`;
  }

  if (factorParts.length) {
    html += `</br><b><font color=#FF6347>—— IP类型风险 ——</font></b></br>`;
    for (const factor of factorParts) {
      const [fname, ...frest] = factor.split("：");
      html += `<b>${fname}</b>：${frest.join("：")}</br>`;
    }
  }

  html += `</br><font color=#6959CD><b>节点</b> ➟ ${nodeName}</font></p>`;

  $done({
    title: "节点 IP 风险汇总",
    htmlMessage: html,
    icon: meta.icon,
    "title-color": meta.color,
  });
})()
.catch((e) => {
  // 异常兜底逻辑
  const errHtml = `<p style="text-align: center; font-family: -apple-system; font-size: large; font-weight: bold;">` +
    `</br></br>🔴 诊断发生异常：${String(e && e.message ? e.message : e)}</p>`;
  $done({
    title: "IP 纯净度",
    htmlMessage: errHtml,
    icon: "network.slash",
  });
});
