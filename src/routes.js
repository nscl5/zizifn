import {
  buildLink,
  safeFetch,
  isInIgnoredRange,
  pick,
  CONST,
  SENS,
  buildMainDomains,
  buildSubscriptionHeaders,
  buildSettingsUrl,
  resolveIPv4ViaDoH,
  fetchDomainIpPool,
  countryCodeToFlagEmoji,
  cacheGetJson,
  cachePutJson,
  pickRandomProxyPort,
} from "./core.js";
import panelB64 from "./panel.b64";
const panelBytes = Uint8Array.from(atob(panelB64), (c) => c.charCodeAt(0));
const panelHtml = new TextDecoder("utf-8").decode(panelBytes);

export async function handleIpSubscription(request, core, userID, hostName, ctx, enhanced = false, cfg = null, env = null) {
  const url = new URL(request.url);
  const subName = url.searchParams.get("name");

  const mainDomains = buildMainDomains(hostName);

  const httpsPorts = [443, 8443, 2053, 2083, 2087, 2096];
  const httpPorts = [80, 8080, 8880, 2052, 2082, 2086, 2095];
  let links = [];
  const isPagesDeployment = hostName.endsWith(".pages.dev");
  // Only xray has a "tcp" preset in CORE_PRESETS (see core.js); "sb" only
  // defines "tls". Including core === "sb" here used to make buildLink()
  // reach CORE_PRESETS.sb.tcp (undefined) and throw, silently truncating
  // the whole /sb subscription partway through the IP loop below.
  const includeTcp = core === "xray" && enhanced && !isPagesDeployment;

  mainDomains.forEach((domain, i) => {
    links.push(
      buildLink({
        core,
        proto: "tls",
        userID,
        hostName,
        address: domain,
        port: pick(httpsPorts),
        tag: `Domain${i + 1}`,
        enhanced,
      }),
    );
  });

  try {
    const cache = caches.default;
    const cacheKey = new Request("https://cf-ip-cache.local");
    let response = await cache.match(cacheKey);
    if (!response) {
      const r = await safeFetch(
        "https://raw.githubusercontent.com/NiREvil/vless/refs/heads/main/Cloudflare-IPs.json",
        {},
        4000,
      );
      if (r.ok) {
        response = new Response(await r.text(), {
          headers: { "Cache-Control": "public, max-age=86400" },
        });
        ctx.waitUntil(cache.put(cacheKey, response.clone()));
      }
    }
    if (response) {
      const json = await response.json();
      const ips = [...(json.ipv4 || []), ...(json.ipv6 || [])]
        .map((x) => x.ip)
        .filter((ip) => !isInIgnoredRange(ip))
        .slice(0, 20);
      ips.forEach((ip, i) => {
        const formattedAddress = ip.includes(":") ? `[${ip}]` : ip;
        links.push(
          buildLink({
            core,
            proto: "tls",
            userID,
            hostName,
            address: formattedAddress,
            port: pick(httpsPorts),
            tag: `IP${i + 1}`,
            enhanced,
          }),
        );
        if (includeTcp) {
          links.push(
            buildLink({
              core,
              proto: "tcp",
              userID,
              hostName,
              address: formattedAddress,
              port: pick(httpPorts),
              tag: `IP${i + 1}`,
              enhanced,
            }),
          );
        }
      });
    }
  } catch (e) {
    console.error("Cached IP fetch failed", e);
  }

  // NAT64 fallback config: identical to the plain worker-domain config,
  // but forces nat64=on in the ws path so it works even if the server
  // default (or the panel toggle) has it off.
  links.push(
    buildLink({
      core,
      proto: "tls",
      userID,
      hostName,
      address: hostName,
      port: 443,
      tag: "NAT64",
      enhanced,
      overrides: { nat64: true },
    }),
  );

  // Top 10 lowest-risk ProxyIP configs, pulled from the same pool the
  // ProxyIPs panel card uses (see buildProxyIpPool above). Each tag
  // encodes country + whether that pool host is domain- or IP-backed;
  // makeName() appends the transport (TLS/TCP) on top of that.
  if (cfg) {
    try {
      const pool = await buildProxyIpPool(cfg, ctx);
      const top10 = [...pool].sort((a, b) => (a.score ?? 999) - (b.score ?? 999)).slice(0, 10);
      top10.forEach((entry, i) => {
        const tag = proxyEntryTag(entry, i);
        const overrides = { proxyIP: `${entry.ip}:${entry.port}` };
        links.push(buildLink({ core, proto: "tls", userID, hostName, address: hostName, port: 443, tag, enhanced, overrides }));
        if (includeTcp) {
          links.push(buildLink({ core, proto: "tcp", userID, hostName, address: hostName, port: 80, tag, enhanced, overrides }));
        }
      });
    } catch (e) {
      console.error("ProxyIP pool for subscription failed", e);
    }
  }

  const headers = {
    "Content-Type": "text/plain;charset=utf-8",
    ...buildSubscriptionHeaders(subName),
  };
  return new Response(btoa(links.join("\n")), { headers });
}

export async function handleMyConnection(request, env, ctx) {
  const clientIP = request.headers.get("CF-Connecting-IP") || "127.0.0.1";
  const cf = request.cf || {};
  let threatScore = 0;
  let risk = "Low";

  try {
    const harmonicaRes = await safeFetch(
      `https://api.harmonica.workers.dev/api/${clientIP}`,
      {
        headers: {
          "User-Agent":
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/149.0.0.0 Safari/537.36",
          Accept: "application/json",
        },
      },
      4000,
    );
    if (harmonicaRes.ok) {
      const data = await harmonicaRes.json();
      if (data) {
        const targetObj = data.info || data;
        threatScore = targetObj.score ?? targetObj.fraud_score ?? targetObj.threatScore ?? 0;
        if (targetObj.risk) risk = targetObj.risk.charAt(0).toUpperCase() + targetObj.risk.slice(1);
      }
    }
  } catch (e) {}

  return new Response(
    JSON.stringify({
      ip: clientIP,
      country: cf.country || "N/A",
      city: cf.city || "",
      isp: cf.asOrganization || "N/A",
      threatScore,
      risk,
    }),
    { headers: { "Content-Type": "application/json", "Access-Control-Allow-Origin": "*" } },
  );
}

export async function handleResolveDomain(request) {
  const url = new URL(request.url);
  const domain = url.searchParams.get("domain");
  if (!domain)
    return new Response(JSON.stringify({ error: "Missing domain" }), {
      status: 400,
      headers: { "Content-Type": "application/json" },
    });

  const headers = { "Content-Type": "application/json", "Access-Control-Allow-Origin": "*" };
  if (/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(domain)) {
    return new Response(JSON.stringify({ ip: domain }), { headers });
  }

  try {
    const dnsRes = await safeFetch(
      `https://1.1.1.1/dns-query?name=${encodeURIComponent(domain)}&type=A`,
      { headers: { accept: "application/dns-json" } },
      4000,
    );
    const dnsData = await dnsRes.json();
    const ipAnswer = dnsData.Answer?.find((a) => a.type === 1);
    return new Response(JSON.stringify({ ip: ipAnswer ? ipAnswer.data : null }), { headers });
  } catch (error) {
    return new Response(JSON.stringify({ ip: null, error: error.toString() }), { headers });
  }
}

// Backs the "Proxy Server" info panel. Used to be two client-side round
// trips (GET /resolve-domain, then the browser itself calling
// https://ipapi.co/...) - meaning that second lookup ran from the
// visitor's own IP/browser, not the worker's. This does the DNS
// resolution + geolocation server-side instead, in one call, reusing the
// same Cache-API-backed per-IP cache as the ProxyIPs pool.
export async function handleProxyHostInfo(request, env, ctx) {
  const url = new URL(request.url);
  const host = url.searchParams.get("host");
  const headers = { "Content-Type": "application/json", "Access-Control-Allow-Origin": "*" };
  if (!host) return new Response(JSON.stringify({ error: true, reason: "Missing host" }), { status: 400, headers });

  try {
    let ip = host;
    if (!/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(host)) {
      const resolved = await resolveIPv4ViaDoH(host);
      if (!resolved) return new Response(JSON.stringify({ error: true, reason: "Could not resolve host" }), { headers });
      ip = resolved;
    }
    const meta = await getIpMeta(ctx, ip);
    return new Response(
      JSON.stringify({
        ip,
        city: meta.city || "",
        country_name: meta.country,
        country_code: meta.countryCode,
        org: meta.org || "",
      }),
      { headers },
    );
  } catch (error) {
    return new Response(JSON.stringify({ error: true, reason: error.toString() }), { headers });
  }
}

// harmonica.workers.dev already returns full geo/ISP data (its `details`
// object: country, country_code, city, isp, organization, ...) right
// alongside the fraud score (`info`), so one call here covers what used
// to take two separate outbound requests (a dedicated geolocation API
// plus this one for risk). One request is also just less exposed to
// rate-limiting than two.
async function FetchIPData(ip) {
  try {
    const res = await safeFetch(
      `https://api.harmonica.workers.dev/api/${ip}`,
      {
        headers: {
          "User-Agent":
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/149.0.0.0 Safari/537.36",
          Accept: "application/json",
        },
      },
      4000,
    );
    if (!res.ok) return null;
    const data = await res.json();
    if (!data) return null;
    const info = data.info || {};
    const details = data.details || {};
    const threatScore = info.score ?? info.fraud_score ?? info.threatScore ?? 0;
    const risk = info.risk ? info.risk.charAt(0).toUpperCase() + info.risk.slice(1) : "Unknown";
    return {
      country: details.country || "Unknown",
      countryCode: (details.country_code || "").toLowerCase(),
      city: details.city || "",
      org: details.isp || details.organization || "",
      score: threatScore,
      risk,
    };
  } catch (e) {
    return null;
  }
}

// Cache-API-backed cache for a single IP's geo+risk lookup (6h TTL, same
// as the pool cache below). A later refresh within that window reuses
// it instead of re-hitting harmonica, which is both what keeps the panel
// from silently losing already-known IPs on refresh and what keeps it
// from re-tripping that service's rate limits every time. A
// failed/"Unknown" lookup is deliberately NOT cached, so the next
// refresh gets to retry it rather than being stuck with "Unknown"
// forever. Unlike a KV-backed cache, this expires on its own - so an IP
// that was only ever seen because a user typed in a wrong/malicious
// ProxyIP domain ages back out instead of leaving bad data around
// indefinitely for whoever looks that IP up next.
async function getIpMeta(ctx, ip) {
  const cacheKey = `ipmeta:${ip}`;
  const cached = await cacheGetJson(cacheKey);
  if (cached) return cached;
  const meta = (await FetchIPData(ip)) || { country: "Unknown", countryCode: "", city: "", org: "", score: 0, risk: "Unknown" };
  if (meta.country && meta.country !== "Unknown") await cachePutJson(ctx, cacheKey, meta);
  return meta;
}

// Same idea as getIpMeta, but for a batch of entries that already came
// back WITH geo/risk data attached (fetchDomainIpPool's response) - an
// already-cached IP's stored data wins over whatever this particular
// response says, so a domain's IPs stay stable across refreshes even if
// the upstream pool API's answer for one of them jitters or degrades.
async function enrichWithPersistentCache(ctx, entries) {
  return Promise.all(
    entries.map(async (entry) => {
      const cacheKey = `ipmeta:${entry.ip}`;
      const cached = await cacheGetJson(cacheKey);
      if (cached) return { ...entry, ...cached };
      if (entry.country && entry.country !== "Unknown") await cachePutJson(ctx, cacheKey, entry);
      return entry;
    }),
  );
}

// Resolves one ProxyIP pool host into its enriched entries. A literal IP
// host is just itself (single geolocate + risk lookup, cached). A
// domain host goes through fetchDomainIpPool, which mirrors the domain's
// whole current IP set - with risk + geo already attached - in one call;
// if that service is down we fall back to a single DoH A-record lookup
// so the feature still degrades gracefully instead of failing outright.
// Note this always re-resolves which IPs currently back the host (so an
// IP removed from the domain naturally stops appearing); only the
// per-IP geo/risk metadata is cached, via getIpMeta/enrichWithPersistentCache.
async function resolveProxyPoolHost(host, port, ctx) {
  const isIPHost = /^\d{1,3}(\.\d{1,3}){3}$/.test(host);

  if (isIPHost) {
    if (isInIgnoredRange(host)) return [];
    const meta = await getIpMeta(ctx, host);
    return [{ host, port, ip: host, hostType: "ip", ...meta }];
  }

  let pool = await fetchDomainIpPool(host);
  if (!pool.length) {
    const single = await resolveIPv4ViaDoH(host);
    if (single) {
      const meta = await getIpMeta(ctx, single);
      pool = [{ ip: single, ...meta }];
    }
  }

  pool = pool.filter((p) => p.ip && !isInIgnoredRange(p.ip));
  pool = await enrichWithPersistentCache(ctx, pool);

  return pool.map((p) => ({
    host,
    port,
    ip: p.ip,
    hostType: "domain",
    country: p.country,
    countryCode: p.countryCode,
    score: p.score,
    risk: p.risk,
  }));
}

// Resolves every host in the configured ProxyIP pool (never the worker's
// own domain - that's the client entry point, not a ProxyIP) to its
// backing IPv4 address(es), each already carrying country + risk info.
// Pool hosts are resolved in parallel (each can itself involve a slow
// upstream call), and the flattened, enriched result is cached for 6h so
// both the panel card and the subscription builder share one lookup -
// unless forceRefresh is set (the panel's Refresh button), which skips
// straight to re-resolving every host's CURRENT IP set while still
// reusing already-known per-IP geo/risk data via the Cache API above.
async function buildProxyIpPool(cfg, ctx, forceRefresh = false) {
  const cache = caches.default;
  const poolCacheKey = new Request("https://cf-proxyip-pool-cache.local");
  if (ctx && !forceRefresh) {
    const cachedRes = await cache.match(poolCacheKey);
    if (cachedRes) return cachedRes.json();
  }

  const seenHosts = new Set();
  const hosts = (cfg.proxyPool || [])
    .map((raw) => {
      const [host, port = "443"] = raw.split(":");
      return { host, port };
    })
    .filter(({ host }) => {
      if (!host || seenHosts.has(host)) return false;
      seenHosts.add(host);
      return true;
    });

  const results = (await Promise.all(hosts.map(({ host, port }) => resolveProxyPoolHost(host, port, ctx)))).flat();

  if (ctx && results.length) {
    const cacheResponse = new Response(JSON.stringify(results), {
      headers: { "Content-Type": "application/json", "Cache-Control": "public, max-age=21600" },
    });
    ctx.waitUntil(cache.put(poolCacheKey, cacheResponse));
  }

  return results;
}

// Turns a resolved+enriched pool entry into a config tag that says, at a
// glance: which country it's in, whether it came from a domain-backed
// pool (which may hold many more IPs than we show) or a fixed IP, and —
// once passed through buildLink/makeName — which transport it uses.
function proxyEntryTag(entry, index) {
  const countryTag = entry.countryCode ? entry.countryCode.toUpperCase() : (entry.country || "XX").slice(0, 2).toUpperCase();
  const flag = countryCodeToFlagEmoji(entry.countryCode);
  const hostTag = entry.hostType === "ip" ? "IP" : "Domain";
  return `${flag}${countryTag}-${hostTag}-${index + 1}`;
}

// Builds a ready-to-copy config pair (Xray + Singbox) for one resolved
// pool entry, tagged the same way the /xray and /sb subscriptions tag
// their own top-10 ProxyIP configs (see proxyEntryTag above), so a name
// like "🇺🇸US-IP-1-TLS" means the same thing everywhere it shows up.
//
// The client-facing port+transport (NOT the proxyIP override, which
// stays entry.ip:entry.port) is randomized per config, per call - so a
// refresh doesn't hand back the exact same "port 443, TLS" pair for
// every single entry. See pickRandomProxyPort() in core.js for why
// *.pages.dev only ever gets a TLS port back.
function buildProxyEntryConfigs(entry, hostName, userID, index) {
  const tag = proxyEntryTag(entry, index);
  const proxyIP = `${entry.ip}:${entry.port}`;
  const isPagesDeployment = hostName.endsWith(".pages.dev");
  const xrayPort = pickRandomProxyPort(isPagesDeployment);
  const sbPort = pickRandomProxyPort(isPagesDeployment);
  const xray = buildLink({
    core: "xray",
    proto: xrayPort.proto,
    userID,
    hostName,
    address: hostName,
    port: xrayPort.port,
    tag,
    overrides: { proxyIP },
  });
  const sb = buildLink({
    core: "sb",
    proto: sbPort.proto,
    userID,
    hostName,
    address: hostName,
    port: sbPort.port,
    tag,
    overrides: { proxyIP },
  });
  return {
    host: entry.host,
    ip: entry.ip,
    hostType: entry.hostType,
    risk: entry.risk,
    score: entry.score,
    configs: [
      { label: "Xray", link: xray },
      { label: "Singbox", link: sb },
    ],
  };
}

// Builds the ProxyIPs panel card data. Entries are grouped two levels
// deep:
//   - by country, so the panel can render one button per country (lowest
//     risk first, see the outer sort below);
//   - within a country, by pool host, so a single domain that resolves to
//     several IPs in that country becomes ONE dropdown (defaulting to its
//     lowest-risk IP) instead of several indistinguishable flat rows.
// Every IP gets 1-2 ready-to-use configs whose ws path carries a
// `proxyip=` override (see withConfigOverrides / core.js and
// parsePathOverrides / network.js) so that IP becomes that config's sole
// fallback route.
export async function handleProxyIpsInfo(request, cfg, hostName, ctx, env) {
  const headers = {
    "Content-Type": "application/json",
    "Access-Control-Allow-Origin": "*",
    "Cache-Control": "public, max-age=21600",
  };

  try {
    const url = new URL(request.url);
    // The panel's Refresh button sends ?refresh=1 to bypass both response
    // caches below and re-resolve every pool host's CURRENT IP set (so an
    // IP a domain no longer resolves to drops off, and a newly-added one
    // shows up) - see buildProxyIpPool. Already-known IPs still don't
    // re-hit harmonica though: that's what the
    // getIpMeta/enrichWithPersistentCache cache in buildProxyIpPool is for.
    const forceRefresh = url.searchParams.get("refresh") === "1";

    const cache = caches.default;
    const cacheKey = new Request(`https://cf-proxyips-cache.local/${hostName}`);
    if (!forceRefresh) {
      const cached = await cache.match(cacheKey);
      if (cached) return cached;
    }

    const enriched = await buildProxyIpPool(cfg, ctx, forceRefresh);

    const countryMap = new Map();
    enriched.forEach((entry) => {
      const countryKey = entry.country || "Unknown";
      if (!countryMap.has(countryKey)) {
        countryMap.set(countryKey, { country: countryKey, countryCode: entry.countryCode || "", hostsMap: new Map() });
      }
      const countryGroup = countryMap.get(countryKey);
      if (!countryGroup.countryCode && entry.countryCode) countryGroup.countryCode = entry.countryCode;
      const hostKey = entry.host;
      if (!countryGroup.hostsMap.has(hostKey)) {
        countryGroup.hostsMap.set(hostKey, { host: hostKey, hostType: entry.hostType, entries: [] });
      }
      countryGroup.hostsMap.get(hostKey).entries.push(entry);
    });

    const groups = [...countryMap.values()]
      .map((countryGroup) => {
        const hosts = [...countryGroup.hostsMap.values()]
          .map((hostGroup) => {
            const sortedEntries = [...hostGroup.entries].sort((a, b) => (a.score ?? 999) - (b.score ?? 999));
            return {
              host: hostGroup.host,
              hostType: hostGroup.hostType,
              entries: sortedEntries.map((entry, i) => buildProxyEntryConfigs(entry, hostName, cfg.userID, i)),
            };
          })
          .sort((a, b) => (a.entries[0]?.score ?? 999) - (b.entries[0]?.score ?? 999));

        const lowestEntry = hosts[0]?.entries[0];
        return {
          country: countryGroup.country,
          countryCode: countryGroup.countryCode,
          flag: countryCodeToFlagEmoji(countryGroup.countryCode),
          lowestScore: lowestEntry?.score ?? null,
          lowestRisk: lowestEntry?.risk ?? "Unknown",
          hosts,
        };
      })
      // Country - risk, ascending: the country holding the single lowest-risk
      // IP overall is shown (as a button) first. Countries with no usable
      // score (lookup failed for every entry) sort to the end.
      .sort((a, b) => (a.lowestScore ?? 999) - (b.lowestScore ?? 999));

    const response = new Response(JSON.stringify({ groups }), { headers });
    if (groups.length) ctx.waitUntil(cache.put(cacheKey, response.clone()));
    return response;
  } catch (e) {
    return new Response(JSON.stringify({ groups: [], error: e.toString() }), { headers });
  }
}

export async function handleConfigPage(userID, hostName, proxyAddress, workerName, nat64 = true) {
  const dream = buildLink({
    core: "xray",
    proto: "tls",
    userID,
    hostName,
    address: hostName,
    port: 443,
    tag: `${hostName}-Xray`,
  });
  const freedom = buildLink({
    core: "sb",
    proto: "tls",
    userID,
    hostName,
    address: hostName,
    port: 443,
    tag: `${hostName}-Singbox`,
  });

  const pattng = buildLink({
    core: "xray",
    proto: "tls",
    userID,
    hostName,
    address: hostName,
    port: 443,
    tag: `${hostName}-PTN`,
    enhanced: true,
  });

  // Precomputed on/off pair for the NAT64 card's copy button. Building
  // both full links here (instead of patching the plain xray-config link
  // client-side, which left the copied config's name unchanged and made
  // it look identical to the regular config) guarantees the copied
  // config is always properly tagged "NAT64" and keeps every other field
  // (alpn included) exactly as buildLink/CORE_PRESETS defines it.
  const nat64On = buildLink({
    core: "xray",
    proto: "tls",
    userID,
    hostName,
    address: hostName,
    port: 443,
    tag: "NAT64",
    overrides: { nat64: true },
  });
  const nat64Off = buildLink({
    core: "xray",
    proto: "tls",
    userID,
    hostName,
    address: hostName,
    port: 443,
    tag: "NAT64",
    overrides: { nat64: false },
  });

  const settingsUrl = buildSettingsUrl(workerName);
  const workerLabel = hostName.split(".")[0] || "INDEX";
  const encodedSubName = encodeURIComponent(workerLabel);
  const subXrayUrlH = `https://${hostName}/xray/${userID}?name=${encodedSubName}`;
  const subXrayUrlV = `https://${hostName}/xray/${userID}#${encodedSubName}`;
  const subXrayUrlVEnhanced = `https://${hostName}/xray-enhanced/${userID}#${encodedSubName}`;
  const subClashUrl = `https://${hostName}/clash/${userID}?name=${encodedSubName}`;
  const subSbUrl = `https://${hostName}/sb/${userID}?name=${encodedSubName}`;
  const subProxyIpsUrl = `https://${hostName}/proxy-ips/${userID}`;

  const finalHTML = panelHtml
  .replace(/{{PROXY_ADDRESS}}/g, proxyAddress)
  .replace(/{{CONFIG_DREAM}}/g, dream)
  .replace(/{{CONFIG_FREEDOM}}/g, freedom)
  .replace(/{{CONFIG_PATTNG}}/g, pattng)
  .replace(/{{NAT64_DEFAULT}}/g, nat64 ? "on" : "off")
  .replace(/{{CONFIG_NAT64_ON}}/g, nat64On)
  .replace(/{{CONFIG_NAT64_OFF}}/g, nat64Off)
  .replace(/{{URL_PROXYIPS}}/g, subProxyIpsUrl)
  .replace(/{{URL_WORKER_SETTINGS}}/g, settingsUrl)
  .replace(/{{URL_V2RAYNG_ENHANCED}}/g, `${SENS.v2rayng()}${subXrayUrlVEnhanced}`)
  .replace(/{{URL_V2RAYNG}}/g, `${SENS.v2rayng()}${subXrayUrlV}`)
  .replace(/{{URL_CLASH}}/g, `${SENS.clash()}${encodeURIComponent(subClashUrl)}`)
  .replace(/{{URL_HIDDIFY}}/g, `${SENS.hiddify()}${encodeURIComponent(subXrayUrlH)}`)
  .replace(/{{URL_EXCLAVE}}/g, `${SENS.exclave()}${encodeURIComponent(subSbUrl)}&name=${encodedSubName}`);

  return new Response(finalHTML, { headers: { "Content-Type": "text/html; charset=utf-8" } });
}
