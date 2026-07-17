/**
 * IP 纯净度与欺诈度多源检测 (Quantumult X 极致并发版)
 * 采用 $task.fetch 原生引擎 + Promise.race 超时赛跑机制
 */

// 基础接口配置
const IPPURE_URL = "https://my.ippure.com/v1/info";
const IPV4_API = "http://ip-api.com/json?lang=zh-CN";
const IPAPI_IS_URL = "https://api.ipapi.is/";
const GLOBAL_TIMEOUT = 3500; // 单个 API 强制超时上限 (毫秒)

// 从 QX 环境获取节点名与参数
const nodeName = getParam("node") || (typeof $environment !== "undefined" && typeof $environment.params === "string" ? $environment.params : "");
const maskIP = readStore("MaskIP") === "true";

// ==================== QX 原生适配与底层工具 ====================

// 兼容获取持久化存储 (QX 使用 $prefs，兼容 $persistentStore)
function readStore(key) {
  if (typeof $prefs !== "undefined" && typeof $prefs.valueForKey === "function") {
    return $prefs.valueForKey(key);
  }
  if (typeof $persistentStore !== "undefined" && typeof $persistentStore.read === "function") {
    return $persistentStore.read(key);
  }
  return null;
}

// 解析 URL 参数或环境参数
function getParam(key) {
  if (typeof $environment !== "undefined" && $environment.sourcePath) {
    const regex = new RegExp(`[?&#]${key}=([^&#]+)`);
    const match = $environment.sourcePath.match(regex);
    if (match) return decodeURIComponent(match[1]);
  }
  return null;
}

// 超时赛跑计时器
function timeout(ms = GLOBAL_TIMEOUT) {
  return new Promise((_, reject) => {
    setTimeout(() => reject(new Error("Request Timeout")), ms);
  });
}

// QX 原生 $task.fetch 封装 (带策略绑定与强制超时)
function httpGet(url, headers = {}) {
  const reqOpts = { url, headers, timeout: GLOBAL_TIMEOUT };
  // 如果绑定了特定节点策略，注入 QX 的 policy 参数
  if (nodeName && typeof nodeName === "string" && nodeName !== "null") {
    reqOpts.opts = { policy: nodeName };
  }
  
  const fetchTask = $task.fetch(reqOpts).then(resp => {
    if (!resp || !resp.body) throw new Error("Empty Response");
    return { resp, data: resp.body };
  });

  // 引入赛跑机制，防止单点 API 卡死整个脚本
  return Promise.race([fetchTask, timeout(GLOBAL_TIMEOUT)]);
}

function safeJsonParse(s) {
  try { return JSON.parse(s); } catch (_) { return null; }
}

function toInt(v) {
  const n = Number(v);
  return Number.isFinite(n) ? Math.round(n) : null;
}

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

function flagEmoji(code) {
  if (!code) return "";
  let c = String(code).toUpperCase();
  if (c === "TW") c = "CN";
  if (c.length !== 2) return "";
  return String.fromCodePoint(...c.split("").map((x) => 127397 + x.charCodeAt(0)));
}

// ==================== 评级与数据解析逻辑 ====================

function severityMeta(sev) {
  if (sev >= 4) return { icon: "xmark.octagon.fill", color: "#8E0000" };
  if (sev >= 3) return { icon: "exclamationmark.triangle.fill", color: "#FF3B30" };
  if (sev >= 2) return { icon: "exclamationmark.circle.fill", color: "#FF9500" };
  if (sev >= 1) return { icon: "exclamationmark.circle", color: "#FFCC00" };
  return { icon: "checkmark.seal.fill", color: "#34C759" };
}

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
  const typeMap = { "DCH": "🏢 数据中心/服务器", "WEB": "🏢 数据中心/服务器", "SES": "🏢 数据中心/服务器", "CDN": "🌐 CDN", "MOB": "📱 蜂窝移动网络", "ISP": "🏠 家庭宽带", "COM": "🏬 商业宽带", "EDU": "🎓 教育网络", "GOV": "🏛️ 政府网络", "MIL": "🎖️ 军用网络", "ORG": "🏢 组织机构", "RES": "🏠 住宅网络" };
  const parts = String(usageType).toUpperCase().split("/");
  const descriptions = [];
  for (const part of parts) {
    if (typeMap[part] && !descriptions.includes(typeMap[part])) descriptions.push(typeMap[part]);
  }
  return descriptions.length === 0 ? `IP类型：❓ ${usageType} ${source}` : `IP类型：${descriptions.join(" / ")} (${usageType}) ${source}`;
}

function isRiskyUsageType(usageType) {
  if (!usageType) return false;
  return String(usageType).toUpperCase().split("/").some(part => ["DCH", "WEB", "SES", "COM", "CDN"].includes(part));
}

function gradeDbip(html) {
  if (!html) return { sev: 2, text: "DB-IP：获取失败" };
  const m = html.match(/Estimated threat level for this IP address is\s*<span[^>]*>\s*([^<\s]+)\s*</i);
  const riskText = (m ? m[1] : "").toLowerCase();
  if (riskText === "high") return { sev: 3, text: "DB-IP：⚠️ 高风险 (high)" };
  if (riskText === "medium") return { sev: 1, text: "DB-IP：🔶 中风险 (medium)" };
  if (riskText === "low") return { sev: 0, text: "DB-IP：✅ 低风险 (low)" };
  return { sev: 2, text: `DB-IP：${riskText || "获取失败"}` };
}

function gradeScamalytics(html) {
  if (!html) return { sev: 2, text: "Scamalytics：获取失败" };
  const m = html.match(/Fraud\s*Score[:\s]*(\d+)/i) || html.match(/class="score"[^>]*>(\d+)/i) || html.match(/"score"\s*:\s*(\d+)/i);
  const s = m ? toInt(m[1]) : null;
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
  const sev = items.includes("Tor") || items.includes("Abuser") ? 3 : items.length >= 2 ? 2 : 1;
  const label = sev >= 3 ? "⚠️ 高风险" : sev >= 2 ? "🔶 较高风险" : "🔶 有标记";
  return { sev, text: `ipregistry：${label} (${items.join("/")})` };
}

// ==================== 异步请求并发任务 ====================

async function fetchIpapi(ip) {
  const { data } = await httpGet(`https://api.ipapi.is/?q=${encodeURIComponent(ip)}`);
  return safeJsonParse(data);
}

async function fetchDbipHtml(ip) {
  const { data } = await httpGet(`https://db-ip.com/${encodeURIComponent(ip)}`);
  return String(data);
}

async function fetchScamalyticsHtml(ip) {
  const { data } = await httpGet(`https://scamalytics.com/ip/${encodeURIComponent(ip)}`);
  return String(data);
}

function extractIpregistrySecurityFlag(html, fieldName) {
  const re = new RegExp(`${fieldName}</span>[\\s\\S]{0,300}?<div class="(?:positive|negative)">[\\s\\S]{0,800}?(Yes|No)</div>`, "i");
  const m = html.match(re);
  return m ? m[1].trim().toLowerCase() === "yes" : null;
}

async function fetchIpregistry(ip) {
  const { data } = await httpGet(`https://ipregistry.co/${encodeURIComponent(ip)}`, {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
  });
  const html = String(data);
  const flags = {
    is_abuser: extractIpregistrySecurityFlag(html, "Abuser"),
    is_attacker: extractIpregistrySecurityFlag(html, "Attacker"),
    is_bogon: extractIpregistrySecurityFlag(html, "Bogon"),
    is_cloud_provider: extractIpregistrySecurityFlag(html, "Cloud Provider"),
    is_proxy: extractIpregistrySecurityFlag(html, "Proxy"),
    is_relay: extractIpregistrySecurityFlag(html, "Relay"),
    is_tor: extractIpregistrySecurityFlag(html, "Tor"),
    is_vpn: extractIpregistrySecurityFlag(html, "VPN"),
    is_anonymous: extractIpregistrySecurityFlag(html, "Anonymous"),
    is_threat: extractIpregistrySecurityFlag(html, "Threat")
  };
  return Object.values(flags).every(v => v === null) ? null : flags;
}

async function fetchIp2locationIo(ip) {
  const { data } = await httpGet(`https://www.ip2location.io/${encodeURIComponent(ip)}`);
  const html = String(data);
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
  const { data } = await httpGet(`https://ipinfo.io/${encodeURIComponent(ip)}`, {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
    "Accept": "text/html"
  });
  const html = String(data);
  const detected = [];
  ["VPN", "Proxy", "Tor", "Relay", "Hosting", "Residential Proxy"].forEach(type => {
    if (new RegExp(`aria-label="${type}\\s+Detected"`, "i").test(html)) detected.push(type);
  });
  const asnTypeMatch = html.match(/>ASN type<\/span>\s*<\/td>\s*<td>([^<]+)</i);
  return { detected, asnType: asnTypeMatch ? asnTypeMatch[1].trim() : null };
}

// ==================== 主程序调度 ====================

;(async () => {
  let ip = null;
  let cachedIpapiResponse = null;

  // 1. 获取 IPv4，容错处理
  try {
    const { data: ipv4Data } = await httpGet(IPV4_API);
    const ipv4Json = safeJsonParse(ipv4Data);
    ip = ipv4Json?.query || ipv4Json?.ip || String(ipv4Data || "").trim();
  } catch (_) { }

  if (!ip) {
    try {
      const { data } = await httpGet(IPAPI_IS_URL);
      cachedIpapiResponse = safeJsonParse(data);
      if (cachedIpapiResponse?.ip) ip = cachedIpapiResponse.ip;
    } catch (_) { }
  }

  if (!ip) {
    $done({ title: "IP 纯净度", htmlMessage: "<p style='text-align: center;'>⚠️ 获取 IPv4 失败，请检查网络或节点状态</p>", icon: "exclamationmark.triangle.fill" });
    return;
  }

  // 2. 发起独立轻量化请求
  let ippureFraudScore = null;
  httpGet(IPPURE_URL).then(({ data }) => {
    const base = safeJsonParse(data);
    if (base) ippureFraudScore = base.fraudScore;
  }).catch(() => {});

  // 3. 高并发多源检测任务池
  const tasks = {
    ipapi: cachedIpapiResponse ? Promise.resolve(cachedIpapiResponse) : fetchIpapi(ip),
    ip2locIo: fetchIp2locationIo(ip),
    ipinfoIo: fetchIpinfoIo(ip),
    dbipHtml: fetchDbipHtml(ip),
    scamHtml: fetchScamalyticsHtml(ip),
    ipregistry: fetchIpregistry(ip),
  };

  // 等待所有的任务赛跑完成（或超时被截断），绝对不会因单点报错崩溃
  const results = await Promise.allSettled(Object.entries(tasks).map(([k, p]) => p.then(v => [k, v])));
  const ok = {};
  results.forEach(r => { if (r.status === "fulfilled" && r.value) ok[r.value[0]] = r.value[1]; });

  // 4. 数据提取与聚合
  const ipapiData = ok.ipapi || {};
  const ip2loc = parseIp2locationIo(ok.ip2locIo);
  const hostingLine = ip2locationHostingText(ip2loc.usageType);

  const ipapiHasLocation = !!(ipapiData.location?.country_code || ipapiData.location?.country);
  const ipapiHasAsn = !!ipapiData.asn?.asn;

  const countryCode = ipapiHasLocation ? ipapiData.location?.country_code : (ip2loc.countryCode || "");
  const country = ipapiHasLocation ? ipapiData.location?.country : (ip2loc.country || "");
  const city = ipapiHasLocation ? ipapiData.location?.city : (ip2loc.city || "");
  const flag = flagEmoji(countryCode);

  let asnText = "-";
  if (ipapiHasAsn) asnText = `AS${ipapiData.asn.asn} ${ipapiData.asn.org || ""}`.trim();
  else if (ip2loc.asn) asnText = `AS${ip2loc.asn} ${ip2loc.asOrg || ""}`.trim();

  // 5. 组装评级
  const grades = [
    gradeIppure(ippureFraudScore),
    gradeIpapi(ok.ipapi),
    gradeIp2locationIo(ip2loc.fraudScore),
    gradeScamalytics(ok.scamHtml),
    gradeDbip(ok.dbipHtml),
    gradeIpregistry(ok.ipregistry)
  ].filter(g => g && g.text);

  const maxSev = grades.reduce((m, g) => Math.max(m, g.sev ?? 2), 0);
  const meta = severityMeta(maxSev);

  // 6. 提取风险因子
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
    const items = ["is_proxy", "is_tor", "is_vpn", "is_datacenter", "is_abuser", "is_crawler"]
      .filter(k => ok.ipapi[k] === true)
      .map(k => k.replace("is_", "").replace(/^[a-z]/, c => c.toUpperCase()));
    if (items.length) factorParts.push(`ipapi 检测类型：${items.join("/")}`);
  }

  if (ok.ipinfoIo?.detected?.length) factorParts.push(`ipinfo.io 检测类型：${ok.ipinfoIo.detected.join("/")}`);

  if (ok.ipregistry) {
    const items = Object.entries(ok.ipregistry)
      .filter(([_, v]) => v === true)
      .map(([k]) => k.replace("is_", "").replace(/^[a-z]/, c => c.toUpperCase()));
    if (items.length) factorParts.push(`ipregistry 检测类型：${items.join("/")}`);
  }

  if (!ip2locProxyItems.length && ip2loc.usageType && isRiskyUsageType(ip2loc.usageType)) {
    const usageDesc = { "DCH": "数据中心", "WEB": "Web托管", "SES": "搜索引擎", "COM": "商业宽带", "CDN": "CDN" };
    factorParts.push(`IP2Location 检测类型：${usageDesc[String(ip2loc.usageType).toUpperCase()] || ip2loc.usageType} (${ip2loc.usageType})`);
  }

  // 7. 渲染 HTML 输出 UI
  let html = `<p style="text-align: center; font-family: -apple-system; font-size: large; font-weight: thin">`;
  html += `<b><font color=#6959CD>IP</font> : </b><font color=>${maskIpAddress(ip)}</font></br>`;
  html += `<b><font color=#6959CD>ASN</font> : </b><font color=>${asnText}</font></br>`;
  html += `<b><font color=#6959CD>位置</font> : </b><font color=>${flag} ${country} ${city}</font></br>`;
  html += `<b><font color=#6959CD>类型</font> : </b><font color=>${hostingLine.replace("IP类型：", "")}</font></br>`;

  html += `</br><b><font color=#FF6347>—— 多源评分 ——</font></b></br>`;
  grades.forEach(g => {
    const [name, ...rest] = g.text.split("：");
    html += `<b>${name}</b>：${rest.join("：")}</br>`;
  });

  if (factorParts.length) {
    html += `</br><b><font color=#FF6347>—— IP类型风险 ——</font></b></br>`;
    factorParts.forEach(f => {
      const [fname, ...frest] = f.split("：");
      html += `<b>${fname}</b>：${frest.join("：")}</br>`;
    });
  }

  html += `</br><font color=#6959CD><b>节点</b> ➟ ${nodeName || "默认直连/全局"}</font>`;
  html += `</p>`;

  $done({
    title: "节点 IP 风险汇总",
    htmlMessage: html,
    icon: meta.icon,
    "title-color": meta.color
  });

})().catch((e) => {
  // 终极防御：如果发生未知的致命语法/内存错误，优雅输出 UI 提示
  const errHtml = `<p style="text-align: center; font-family: -apple-system; font-size: large; font-weight: bold;">` +
    `</br></br>🔴 诊断运行异常：${String(e?.message || e)}</p>`;
  $done({
    title: "IP 纯净度 (异常)",
    htmlMessage: errHtml,
    icon: "exclamationmark.triangle.fill",
    "title-color": "#FF3B30"
  });
});
