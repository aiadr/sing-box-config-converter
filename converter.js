(function (root, factory) {
  if (typeof module === "object" && module.exports) {
    module.exports = factory();
  } else {
    root.VlessSingBoxConverter = factory();
  }
})(typeof globalThis !== "undefined" ? globalThis : this, function () {
  "use strict";

  const DEFAULT_TEST_URL = "https://www.gstatic.com/generate_204";
  const DEFAULT_INTERVAL = "3m";

  function decodeText(value) {
    if (!value) return "";
    try {
      return decodeURIComponent(value);
    } catch (_) {
      return value;
    }
  }

  function compactObject(value) {
    if (Array.isArray(value)) {
      return value
        .map(compactObject)
        .filter((item) => item !== undefined && item !== null && item !== "");
    }
    if (!value || typeof value !== "object") return value;

    const result = {};
    for (const [key, item] of Object.entries(value)) {
      const next = compactObject(item);
      const emptyArray = Array.isArray(next) && next.length === 0;
      const emptyObject =
        next && typeof next === "object" && !Array.isArray(next) && Object.keys(next).length === 0;
      if (next !== undefined && next !== null && next !== "" && !emptyArray && !emptyObject) {
        result[key] = next;
      }
    }
    return result;
  }

  function boolParam(params, names) {
    for (const name of names) {
      const value = params.get(name);
      if (value == null) continue;
      return /^(1|true|yes)$/i.test(value);
    }
    return undefined;
  }

  function firstParam(params, names) {
    for (const name of names) {
      const value = params.get(name);
      if (value != null && value !== "") return decodeText(value);
    }
    return "";
  }

  function splitList(value) {
    return String(value || "")
      .split(",")
      .map((item) => item.trim())
      .filter(Boolean);
  }

  function normalizeServerName(value) {
    return String(value || "").replace(/^\[|\]$/g, "");
  }

  function uniqueTag(base, used) {
    const fallback = "proxy";
    const normalized =
      String(base || fallback)
        .trim()
        .replace(/\s+/g, "-")
        .replace(/[^\w.@-]+/g, "")
        .replace(/^-+|-+$/g, "") || fallback;

    let tag = normalized;
    let index = 2;
    while (used.has(tag)) {
      tag = `${normalized}-${index}`;
      index += 1;
    }
    used.add(tag);
    return tag;
  }

  function parseVlessLinks(input, options) {
    const usedTags = new Set(options && options.usedTags ? options.usedTags : []);
    const source = String(input || "").trim();
    if (!source) return [];

    const chunks = source
      .split(/\r?\n/)
      .map((line) => line.trim())
      .filter(Boolean);

    const links = chunks.length ? chunks : [source];
    return links.map((link, index) => parseVlessLink(link, usedTags, index));
  }

  function parseVlessLink(link, usedTags, index) {
    if (!/^vless:\/\//i.test(link)) {
      throw new Error(`Строка ${index + 1}: ожидалась ссылка vless://`);
    }

    let url;
    try {
      url = new URL(link);
    } catch (error) {
      throw new Error(`Строка ${index + 1}: ссылка не разобрана (${error.message})`);
    }

    const params = url.searchParams;
    const security = (params.get("security") || "none").toLowerCase();
    const network = (params.get("type") || params.get("network") || "tcp").toLowerCase();
    const server = normalizeServerName(url.hostname);
    const uuid = decodeText(url.username);
    const port = Number(url.port || (security === "tls" || security === "reality" ? 443 : 80));
    const label = decodeText(url.hash ? url.hash.slice(1) : "") || `${server || "proxy"}-${index + 1}`;

    if (!uuid) throw new Error(`Строка ${index + 1}: не найден UUID`);
    if (!server) throw new Error(`Строка ${index + 1}: не найден сервер`);
    if (!Number.isInteger(port) || port < 1 || port > 65535) {
      throw new Error(`Строка ${index + 1}: некорректный порт`);
    }

    const outbound = {
      type: "vless",
      tag: uniqueTag(label, usedTags),
      server,
      server_port: port,
      uuid,
    };

    const flow = firstParam(params, ["flow"]);
    if (flow) outbound.flow = flow;

    const packetEncoding = firstParam(params, ["packetEncoding", "packet_encoding"]);
    if (packetEncoding) outbound.packet_encoding = packetEncoding;

    if (security === "tls" || security === "reality") {
      const tls = { enabled: true };
      const serverName = firstParam(params, ["sni", "peer", "serverName"]);
      const fingerprint = firstParam(params, ["fp", "fingerprint"]);
      const alpn = splitList(firstParam(params, ["alpn"]));
      const insecure = boolParam(params, ["allowInsecure", "allow_insecure"]);

      if (serverName) tls.server_name = serverName;
      if (alpn.length) tls.alpn = alpn;
      if (typeof insecure === "boolean") tls.insecure = insecure;
      if (fingerprint && fingerprint !== "none") {
        tls.utls = { enabled: true, fingerprint };
      }

      if (security === "reality") {
        tls.reality = {
          enabled: true,
          public_key: firstParam(params, ["pbk", "publicKey", "public_key"]),
          short_id: firstParam(params, ["sid", "shortId", "short_id"]),
          spider_x: firstParam(params, ["spx", "spiderX", "spider_x"]),
        };
      }

      outbound.tls = compactObject(tls);
    }

    const transport = transportFromParams(network, params);
    if (transport) outbound.transport = compactObject(transport);

    const multiplexEnabled = boolParam(params, ["mux", "multiplex"]);
    if (typeof multiplexEnabled === "boolean") {
      outbound.multiplex = { enabled: multiplexEnabled };
    }

    return compactObject(outbound);
  }

  function transportFromParams(network, params) {
    if (!network || network === "tcp") {
      const headerType = (params.get("headerType") || "").toLowerCase();
      if (headerType !== "http") return null;
      const host = splitList(firstParam(params, ["host"]));
      return { type: "http", host, path: firstParam(params, ["path"]) };
    }

    if (network === "ws" || network === "websocket") {
      const host = firstParam(params, ["host"]);
      const headers = host ? { Host: host } : undefined;
      return {
        type: "ws",
        path: firstParam(params, ["path"]) || "/",
        headers,
        max_early_data: numericParam(params, ["ed", "earlyData"]),
        early_data_header_name: firstParam(params, ["eh", "earlyDataHeaderName"]),
      };
    }

    if (network === "grpc") {
      return {
        type: "grpc",
        service_name: firstParam(params, ["serviceName", "service_name"]),
        idle_timeout: firstParam(params, ["idleTimeout", "idle_timeout"]),
        ping_timeout: firstParam(params, ["pingTimeout", "ping_timeout"]),
        permit_without_stream: boolParam(params, ["permitWithoutStream", "permit_without_stream"]),
      };
    }

    if (network === "http" || network === "h2") {
      const host = splitList(firstParam(params, ["host"]));
      return { type: "http", host, path: firstParam(params, ["path"]) };
    }

    if (network === "quic") return { type: "quic" };
    if (network === "httpupgrade" || network === "http_upgrade") {
      const host = firstParam(params, ["host"]);
      return {
        type: "httpupgrade",
        path: firstParam(params, ["path"]) || "/",
        headers: host ? { Host: host } : undefined,
      };
    }

    return { type: network };
  }

  function numericParam(params, names) {
    const value = firstParam(params, names);
    if (!value) return undefined;
    const parsed = Number(value);
    return Number.isFinite(parsed) ? parsed : undefined;
  }

  function buildSingBoxConfig(input, settings) {
    const options = Object.assign(
      {
        fullConfig: true,
        useUrlTest: true,
        selectorTag: "auto",
        testUrl: DEFAULT_TEST_URL,
        interval: DEFAULT_INTERVAL,
        tolerance: 50,
      },
      settings || {}
    );
    const outbounds = parseVlessLinks(input);
    if (!outbounds.length) throw new Error("Добавьте хотя бы одну VLESS-ссылку");

    const proxyTags = outbounds.map((item) => item.tag);
    const withUrlTest = options.useUrlTest && outbounds.length > 1;
    const selectorTag = uniqueTag(options.selectorTag || "auto", new Set(proxyTags));
    const resultOutbounds = [];

    if (withUrlTest) {
      resultOutbounds.push(
        compactObject({
          type: "urltest",
          tag: selectorTag,
          outbounds: proxyTags,
          url: options.testUrl || DEFAULT_TEST_URL,
          interval: options.interval || DEFAULT_INTERVAL,
          tolerance: Number(options.tolerance) || undefined,
        })
      );
    }

    resultOutbounds.push(...outbounds);

    if (!options.fullConfig) {
      return {
        outbounds: resultOutbounds,
      };
    }

    const finalTag = withUrlTest ? selectorTag : proxyTags[0];
    return {
      log: { level: "info" },
      dns: {
        servers: [
          {
            tag: "dns-remote",
            address: "8.8.8.8",
          },
        ],
        final: "dns-remote",
        strategy: "ipv4_only",
      },
      inbounds: [
        {
          type: "tun",
          tag: "tun-in",
          address: ["172.19.0.1/30"],
          auto_route: true,
          strict_route: true,
        },
      ],
      outbounds: resultOutbounds,
      route: {
        rules: [
          {
            action: "sniff",
          },
          {
            protocol: "dns",
            action: "hijack-dns",
          },
        ],
        auto_detect_interface: true,
        final: finalTag,
      },
    };
  }

  function parseSingBoxInput(input) {
    const text = String(input || "").trim();
    if (!text) throw new Error("Вставьте JSON sing-box");
    try {
      return JSON.parse(text);
    } catch (error) {
      throw new Error(`JSON не разобран: ${error.message}`);
    }
  }

  function extractVlessOutbounds(config) {
    if (Array.isArray(config)) {
      return config.filter((item) => item && item.type === "vless");
    }
    if (config && config.type === "vless") return [config];
    if (config && Array.isArray(config.outbounds)) {
      return config.outbounds.filter((item) => item && item.type === "vless");
    }
    return [];
  }

  function singBoxToVlessLinks(input) {
    const config = typeof input === "string" ? parseSingBoxInput(input) : input;
    const outbounds = extractVlessOutbounds(config);
    if (!outbounds.length) throw new Error("В JSON не найдены outbound-объекты type: vless");
    return outbounds.map(outboundToVlessLink);
  }

  function outboundToVlessLink(outbound) {
    const uuid = outbound.uuid || "";
    const server = outbound.server || "";
    const port = outbound.server_port || 443;
    if (!uuid || !server) throw new Error(`Outbound ${outbound.tag || ""}: не хватает uuid/server`);

    const params = new URLSearchParams();
    params.set("encryption", "none");

    if (outbound.flow) params.set("flow", outbound.flow);
    if (outbound.packet_encoding) params.set("packetEncoding", outbound.packet_encoding);
    if (outbound.multiplex && typeof outbound.multiplex.enabled === "boolean") {
      params.set("mux", String(outbound.multiplex.enabled));
    }

    const tls = outbound.tls;
    if (tls && tls.enabled) {
      params.set("security", tls.reality && tls.reality.enabled ? "reality" : "tls");
      if (tls.server_name) params.set("sni", tls.server_name);
      if (Array.isArray(tls.alpn) && tls.alpn.length) params.set("alpn", tls.alpn.join(","));
      if (tls.insecure) params.set("allowInsecure", "1");
      if (tls.utls && tls.utls.fingerprint) params.set("fp", tls.utls.fingerprint);
      if (tls.reality && tls.reality.enabled) {
        if (tls.reality.public_key) params.set("pbk", tls.reality.public_key);
        if (tls.reality.short_id) params.set("sid", tls.reality.short_id);
        if (tls.reality.spider_x) params.set("spx", tls.reality.spider_x);
      }
    } else {
      params.set("security", "none");
    }

    addTransportParams(params, outbound.transport);

    const host = server.includes(":") && !server.startsWith("[") ? `[${server}]` : server;
    const hash = outbound.tag ? `#${encodeURIComponent(outbound.tag)}` : "";
    return `vless://${encodeURIComponent(uuid)}@${host}:${port}?${params.toString()}${hash}`;
  }

  function addTransportParams(params, transport) {
    if (!transport || !transport.type || transport.type === "tcp") {
      params.set("type", "tcp");
      return;
    }

    params.set("type", transport.type === "websocket" ? "ws" : transport.type);

    if (transport.type === "ws" || transport.type === "websocket") {
      if (transport.path) params.set("path", transport.path);
      const host = transport.headers && (transport.headers.Host || transport.headers.host);
      if (host) params.set("host", host);
      if (transport.max_early_data) params.set("ed", String(transport.max_early_data));
      if (transport.early_data_header_name) params.set("eh", transport.early_data_header_name);
      return;
    }

    if (transport.type === "grpc") {
      if (transport.service_name) params.set("serviceName", transport.service_name);
      return;
    }

    if (transport.type === "http" || transport.type === "h2") {
      const host = Array.isArray(transport.host) ? transport.host.join(",") : transport.host;
      if (host) params.set("host", host);
      if (transport.path) params.set("path", transport.path);
      return;
    }

    if (transport.type === "httpupgrade" || transport.type === "http_upgrade") {
      if (transport.path) params.set("path", transport.path);
      const host = transport.headers && (transport.headers.Host || transport.headers.host);
      if (host) params.set("host", host);
    }
  }

  function formatJson(value) {
    return JSON.stringify(value, null, 2);
  }

  return {
    buildSingBoxConfig,
    parseVlessLink,
    parseVlessLinks,
    singBoxToVlessLinks,
    outboundToVlessLink,
    formatJson,
  };
});
