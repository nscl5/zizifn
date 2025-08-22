import { connect } from "cloudflare:sockets";

// Constants
const VLESS_CONSTANTS = {
  VERSION: 1,
  COMMANDS: {
    TCP: 1,
    UDP: 2
  },
  ADDRESS_TYPES: {
    IPV4: 1,
    DOMAIN: 2,
    IPV6: 3
  },
  WS_STATES: {
    OPEN: 1,
    CLOSING: 2
  },
  DNS_PORT: 53,
  DEFAULT_PORT: 443
};

const ENCODED_CONFIG = {
  NETWORK: "c3c=", // ws reversed + base64
  TYPE: "YW5haWQ=", // diana
  STREAM: "bWFlcnRz", // stream
  PROTOCOL: "c3NlbHY=", // vless
};

const API_ENDPOINTS = {
  SCAMALYTICS_BASE: "https://api11.scamalytics.com/v3/",
  GEOIP_PRIMARY: "https://ip-api.io/json/",
  GEOIP_FALLBACK: "http://ip-api.com/json/"
};

// Configuration class to manage settings
class ProxyConfig {
  constructor(env) {
    this.userCode = env.UUID || "dd0cfef0-fda9-47ec-8a65-49d7bc004f82";
    this.proxyIP = env.PROXYIP || "turk.radicalization.ir";
    this.dnsResolver = env.DNS_RESOLVER || "1.1.1.1";
    this.scamalyticsUsername = env.SCAMALYTICS_USERNAME;
    this.scamalyticsApiKey = env.SCAMALYTICS_API_KEY;
  }

  isValidUserCode(code) {
    const UUID_REGEX = /^[0-9a-f]{8}-[0-9a-f]{4}-[4][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
    return UUID_REGEX.test(code);
  }

  hasValidScamalyticsCredentials() {
    return this.scamalyticsUsername && 
           this.scamalyticsApiKey && 
           this.scamalyticsUsername !== '<YOUR_SCAMALYTICS_USERNAME>' &&
           this.scamalyticsApiKey !== '<YOUR_SCAMALYTICS_API_KEY>';
  }
}

// Utility functions
function encodeSecure(str) {
  return btoa(str.split("").reverse().join(""));
}

function decodeSecure(encoded) {
  return atob(encoded).split("").reverse().join("");
}

function base64ToArrayBuffer(base64Str) {
  if (!base64Str) {
    return { error: null };
  }
  try {
    const cleanBase64 = base64Str.replace(/-/g, "+").replace(/_/g, "/");
    const decoded = atob(cleanBase64);
    const arrayBuffer = Uint8Array.from(decoded, (char) => char.charCodeAt(0));
    return { earlyData: arrayBuffer.buffer, error: null };
  } catch (error) {
    return { error };
  }
}

function safeCloseWebSocket(socket) {
  try {
    if (socket.readyState === VLESS_CONSTANTS.WS_STATES.OPEN || 
        socket.readyState === VLESS_CONSTANTS.WS_STATES.CLOSING) {
      socket.close();
    }
  } catch (error) {
    console.error("safeCloseWebSocket error", error);
  }
}

// UUID utilities
const byteToHex = Array.from({ length: 256 }, (_, i) => 
  (i + 256).toString(16).slice(1)
);

function unsafeStringify(arr, offset = 0) {
  const parts = [
    byteToHex[arr[offset + 0]] + byteToHex[arr[offset + 1]] + 
    byteToHex[arr[offset + 2]] + byteToHex[arr[offset + 3]],
    byteToHex[arr[offset + 4]] + byteToHex[arr[offset + 5]],
    byteToHex[arr[offset + 6]] + byteToHex[arr[offset + 7]],
    byteToHex[arr[offset + 8]] + byteToHex[arr[offset + 9]],
    byteToHex[arr[offset + 10]] + byteToHex[arr[offset + 11]] + 
    byteToHex[arr[offset + 12]] + byteToHex[arr[offset + 13]] + 
    byteToHex[arr[offset + 14]] + byteToHex[arr[offset + 15]]
  ];
  return parts.join("-").toLowerCase();
}

function stringify(arr, offset = 0) {
  const uuid = unsafeStringify(arr, offset);
  const config = new ProxyConfig({});
  if (!config.isValidUserCode(uuid)) {
    throw new TypeError("Stringified UUID is invalid");
  }
  return uuid;
}

// Request handlers
class RequestHandler {
  constructor(config) {
    this.config = config;
  }

  async handleStaticRoutes(request, url) {
    switch (url.pathname) {
      case '/':
      case `/${this.config.userCode}`:
        return this.handleHomePage(request);
      case '/api/ip':
        return this.handleClientIPEndpoint(request);
      case '/scamalytics-lookup':
        return this.handleScamalyticsLookup(request, url);
      default:
        if (url.pathname.startsWith('/api/geoip/')) {
          return this.handleGeoIPLookup(url);
        }
        return new Response('Not found', { status: 404 });
    }
  }

  async handleHomePage(request) {
    const hostName = request.headers.get('Host');
    const html = await generateHTML(this.config.userCode, hostName, this.config.proxyIP);
    return new Response(html, {
      headers: { "Content-Type": "text/html;charset=UTF-8" }
    });
  }

  handleClientIPEndpoint(request) {
    const clientIP = request.headers.get('CF-Connecting-IP');
    return new Response(JSON.stringify({ ip: clientIP }), {
      headers: {
        "Content-Type": "application/json",
        "Access-Control-Allow-Origin": "*"
      }
    });
  }

  async handleScamalyticsLookup(request, url) {
    const ipToLookup = url.searchParams.get('ip');
    if (!ipToLookup) {
      return new Response('Missing IP parameter', { status: 400 });
    }

    if (!this.config.hasValidScamalyticsCredentials()) {
      console.error('Scamalytics credentials not configured in Worker.');
      return new Response('Scamalytics API credentials not configured on server.', { 
        status: 500 
      });
    }

    const scamalyticsUrl = `${API_ENDPOINTS.SCAMALYTICS_BASE}${this.config.scamalyticsUsername}/?key=${this.config.scamalyticsApiKey}&ip=${ipToLookup}`;
    
    try {
      const response = await fetch(scamalyticsUrl);
      const responseBody = await response.json();
      
      return new Response(JSON.stringify(responseBody), {
        status: response.status,
        headers: {
          'Content-Type': 'application/json',
          'Access-Control-Allow-Origin': '*',
          'Access-Control-Allow-Methods': 'GET, OPTIONS',
          'Access-Control-Allow-Headers': 'Content-Type'
        }
      });
    } catch (error) {
      console.error('Error fetching from Scamalytics API:', error);
      return new Response(
        JSON.stringify({ 
          error: 'Failed to fetch from Scamalytics API', 
          details: error.message 
        }), 
        {
          status: 502,
          headers: { 
            'Content-Type': 'application/json', 
            'Access-Control-Allow-Origin': '*' 
          }
        }
      );
    }
  }

  async handleGeoIPLookup(url) {
    const ip = url.pathname.split('/')[3];
    if (!ip) {
      return new Response('Missing IP parameter in path', { status: 400 });
    }

    const geoData = await fetchGeoIPWithFallback(ip);
    if (geoData) {
      return new Response(JSON.stringify(geoData), {
        headers: {
          'Content-Type': 'application/json',
          'Access-Control-Allow-Origin': '*'
        }
      });
    }

    return new Response(
      JSON.stringify({ error: 'Failed to fetch GeoIP data from all sources' }), 
      {
        status: 502,
        headers: {
          'Content-Type': 'application/json',
          'Access-Control-Allow-Origin': '*'
        }
      }
    );
  }
}

// WebSocket stream handler
class WebSocketStreamHandler {
  constructor(config) {
    this.config = config;
  }

  async handle(request) {
    const webSocketPair = new WebSocketPair();
    const [client, webSocket] = Object.values(webSocketPair);
    webSocket.accept();

    let address = "";
    let portWithRandomLog = "";
    const log = (info, event) => {
      console.log(`[${address}:${portWithRandomLog}] ${info}`, event || "");
    };

    const earlyDataHeader = request.headers.get("sec-websocket-protocol") || "";
    const readableWebSocketStream = this.makeReadableWebSocketStream(webSocket, earlyDataHeader, log);
    let remoteSocketWrapper = { value: null };
    let udpStreamWrite = null;
    let isDNS = false;

    const streamProcessor = new StreamProcessor(this.config, log);

    readableWebSocketStream
      .pipeTo(
        new WritableStream({
          async write(chunk, controller) {
            if (isDNS && udpStreamWrite) {
              return udpStreamWrite(chunk);
            }
            
            if (remoteSocketWrapper.value) {
              const writer = remoteSocketWrapper.value.writable.getWriter();
              await writer.write(chunk);
              writer.releaseLock();
              return;
            }

            const streamHeader = streamProcessor.processStreamHeader(chunk);
            
            if (streamHeader.hasError) {
              throw new Error(streamHeader.message);
            }

            address = streamHeader.addressRemote;
            const protocol = streamHeader.isUDP ? "udp" : "tcp";
            portWithRandomLog = `${streamHeader.portRemote}--${Math.random()} ${protocol}`;

            if (streamHeader.isUDP) {
              if (streamHeader.portRemote === VLESS_CONSTANTS.DNS_PORT) {
                isDNS = true;
              } else {
                throw new Error("UDP proxy only enable for DNS which is port 53");
              }
            }

            const streamResponseHeader = new Uint8Array([streamHeader.streamVersion[0], 0]);
            const rawClientData = chunk.slice(streamHeader.rawDataIndex);

            if (isDNS) {
              const udpHandler = new UDPHandler(streamProcessor.config, log);
              const { write } = await udpHandler.handleOutBound(webSocket, streamResponseHeader);
              udpStreamWrite = write;
              udpStreamWrite(rawClientData);
              return;
            }

            const tcpHandler = new TCPHandler(streamProcessor.config, log);
            await tcpHandler.handleOutBound(
              remoteSocketWrapper,
              streamHeader.addressRemote,
              streamHeader.portRemote,
              rawClientData,
              webSocket,
              streamResponseHeader
            );
          },
          close() { log("readableWebSocketStream is close"); },
          abort(reason) { log("readableWebSocketStream is abort", JSON.stringify(reason)); }
        })
      )
      .catch((err) => { 
        log("readableWebSocketStream pipeTo error", err); 
      });

    return new Response(null, { status: 101, webSocket: client });
  }

  makeReadableWebSocketStream(webSocketServer, earlyDataHeader, log) {
    let readableStreamCancel = false;
    
    const stream = new ReadableStream({
      start(controller) {
        webSocketServer.addEventListener("message", (event) => {
          if (readableStreamCancel) return;
          controller.enqueue(event.data);
        });
        
        webSocketServer.addEventListener("close", () => {
          safeCloseWebSocket(webSocketServer);
          if (readableStreamCancel) return;
          controller.close();
        });
        
        webSocketServer.addEventListener("error", (err) => {
          log("webSocketServer has error");
          controller.error(err);
        });
        
        const { earlyData, error } = base64ToArrayBuffer(earlyDataHeader);
        if (error) {
          controller.error(error);
        } else if (earlyData) {
          controller.enqueue(earlyData);
        }
      },
      pull(controller) {},
      cancel(reason) {
        if (readableStreamCancel) return;
        log(`ReadableStream was canceled, due to ${reason}`);
        readableStreamCancel = true;
        safeCloseWebSocket(webSocketServer);
      }
    });
    
    return stream;
  }
}

// Stream processing logic
class StreamProcessor {
  constructor(config, log) {
    this.config = config;
    this.log = log;
  }

  processStreamHeader(chunk) {
    const MIN_HEADER_LENGTH = 24;
    if (chunk.byteLength < MIN_HEADER_LENGTH) {
      return { hasError: true, message: "invalid data" };
    }

    const version = new Uint8Array(chunk.slice(0, 1));
    const userValidation = this.validateUser(chunk);
    if (!userValidation.isValid) {
      return { hasError: true, message: userValidation.message };
    }

    const commandInfo = this.parseCommand(chunk);
    if (commandInfo.hasError) {
      return commandInfo;
    }

    const addressInfo = this.parseAddress(chunk, commandInfo.addressIndex);
    if (addressInfo.hasError) {
      return addressInfo;
    }

    return {
      hasError: false,
      addressRemote: addressInfo.addressValue,
      addressType: addressInfo.addressType,
      portRemote: commandInfo.portRemote,
      rawDataIndex: addressInfo.rawDataIndex,
      streamVersion: version,
      isUDP: commandInfo.isUDP
    };
  }

  validateUser(chunk) {
    try {
      const userUUID = stringify(new Uint8Array(chunk.slice(1, 17)));
      const isValid = userUUID === this.config.userCode;
      return { 
        isValid, 
        message: isValid ? "valid user" : "invalid user" 
      };
    } catch (error) {
      return { isValid: false, message: "invalid user format" };
    }
  }

  parseCommand(chunk) {
    const OPTION_LENGTH_INDEX = 17;
    const optLength = new Uint8Array(chunk.slice(OPTION_LENGTH_INDEX, OPTION_LENGTH_INDEX + 1))[0];
    const commandIndex = 18 + optLength;
    const command = new Uint8Array(chunk.slice(commandIndex, commandIndex + 1))[0];

    let isUDP = false;
    if (command === VLESS_CONSTANTS.COMMANDS.TCP) {
      // TCP command
    } else if (command === VLESS_CONSTANTS.COMMANDS.UDP) {
      isUDP = true;
    } else {
      return { 
        hasError: true, 
        message: `command ${command} is not supported` 
      };
    }

    const portIndex = commandIndex + 1;
    const portRemote = new DataView(chunk.slice(portIndex, portIndex + 2)).getUint16(0);
    const addressIndex = portIndex + 2;

    return {
      hasError: false,
      isUDP,
      portRemote,
      addressIndex
    };
  }

  parseAddress(chunk, addressIndex) {
    const addressType = new Uint8Array(chunk.slice(addressIndex, addressIndex + 1))[0];
    let addressLength = 0;
    let addressValueIndex = addressIndex + 1;
    let addressValue = "";

    switch (addressType) {
      case VLESS_CONSTANTS.ADDRESS_TYPES.IPV4:
        addressLength = 4;
        addressValue = new Uint8Array(
          chunk.slice(addressValueIndex, addressValueIndex + addressLength)
        ).join(".");
        break;

      case VLESS_CONSTANTS.ADDRESS_TYPES.DOMAIN:
        addressLength = new Uint8Array(
          chunk.slice(addressValueIndex, addressValueIndex + 1)
        )[0];
        addressValueIndex += 1;
        addressValue = new TextDecoder().decode(
          chunk.slice(addressValueIndex, addressValueIndex + addressLength)
        );
        break;

      case VLESS_CONSTANTS.ADDRESS_TYPES.IPV6:
        addressLength = 16;
        const dataView = new DataView(
          chunk.slice(addressValueIndex, addressValueIndex + addressLength)
        );
        const ipv6Parts = [];
        for (let i = 0; i < 8; i++) {
          ipv6Parts.push(dataView.getUint16(i * 2).toString(16));
        }
        addressValue = ipv6Parts.join(":");
        break;

      default:
        return { 
          hasError: true, 
          message: `invalid addressType: ${addressType}` 
        };
    }

    if (!addressValue) {
      return { hasError: true, message: "addressValue is empty" };
    }

    return {
      hasError: false,
      addressType,
      addressValue,
      rawDataIndex: addressValueIndex + addressLength
    };
  }
}

// TCP connection handler
class TCPHandler {
  constructor(config, log) {
    this.config = config;
    this.log = log;
  }

  async handleOutBound(remoteSocket, addressRemote, portRemote, rawClientData, webSocket, streamResponseHeader) {
    const connectAndWrite = async (address, port) => {
      const tcpSocket = connect({ hostname: address, port: port });
      remoteSocket.value = tcpSocket;
      this.log(`connected to ${address}:${port}`);
      const writer = tcpSocket.writable.getWriter();
      await writer.write(rawClientData);
      writer.releaseLock();
      return tcpSocket;
    };

    const retry = async () => {
      const tcpSocket = await connectAndWrite(this.config.proxyIP || addressRemote, portRemote);
      tcpSocket.closed
        .catch(error => console.log("retry tcpSocket closed error", error))
        .finally(() => safeCloseWebSocket(webSocket));
      await this.remoteSocketToWS(tcpSocket, webSocket, streamResponseHeader, null);
    };

    const tcpSocket = await connectAndWrite(addressRemote, portRemote);
    await this.remoteSocketToWS(tcpSocket, webSocket, streamResponseHeader, retry);
  }

  async remoteSocketToWS(remoteSocket, webSocket, streamResponseHeader, retry) {
    let vlessHeader = streamResponseHeader;
    let hasIncomingData = false;
    
    await remoteSocket.readable
      .pipeTo(
        new WritableStream({
          async write(chunk, controller) {
            hasIncomingData = true;
            if (webSocket.readyState !== VLESS_CONSTANTS.WS_STATES.OPEN) {
              controller.error("webSocket is not open");
              return;
            }
            
            if (vlessHeader) {
              webSocket.send(await new Blob([vlessHeader, chunk]).arrayBuffer());
              vlessHeader = null;
            } else {
              webSocket.send(chunk);
            }
          },
          close() { 
            this.log("remoteConnection readable close"); 
          },
          abort(reason) { 
            console.error("remoteConnection readable abort", reason); 
          }
        })
      )
      .catch(error => {
        console.error("remoteSocketToWS has error", error.stack || error);
        safeCloseWebSocket(webSocket);
      });

    if (hasIncomingData === false && retry) {
      this.log("retry connection");
      await retry();
    }
  }
}

// UDP/DNS handler
class UDPHandler {
  constructor(config, log) {
    this.config = config;
    this.log = log;
  }

  async handleOutBound(webSocket, streamResponseHeader) {
    let isHeaderSent = false;
    
    const transformStream = new TransformStream({
      transform(chunk, controller) {
        for (let index = 0; index < chunk.byteLength;) {
          const lengthBuffer = chunk.slice(index, index + 2);
          const udpPacketLength = new DataView(lengthBuffer).getUint16(0);
          const udpData = new Uint8Array(
            chunk.slice(index + 2, index + 2 + udpPacketLength)
          );
          index = index + 2 + udpPacketLength;
          controller.enqueue(udpData);
        }
      }
    });

    const dnsQueryHandler = new WritableStream({
      write: async (chunk) => {
        try {
          const dnsResponse = await fetch(`https://${this.config.dnsResolver}/dns-query`, {
            method: "POST",
            headers: { "content-type": "application/dns-message" },
            body: chunk
          });
          
          const dnsQueryResult = await dnsResponse.arrayBuffer();
          const udpSize = dnsQueryResult.byteLength;
          const udpSizeBuffer = new Uint8Array([
            (udpSize >> 8) & 0xff, 
            udpSize & 0xff
          ]);
          
          if (webSocket.readyState === VLESS_CONSTANTS.WS_STATES.OPEN) {
            this.log(`dns query success, length: ${udpSize}`);
            
            const responseData = isHeaderSent 
              ? await new Blob([udpSizeBuffer, dnsQueryResult]).arrayBuffer()
              : await new Blob([streamResponseHeader, udpSizeBuffer, dnsQueryResult]).arrayBuffer();
            
            webSocket.send(responseData);
            isHeaderSent = true;
          }
        } catch (error) {
          this.log("DNS query error: " + error);
        }
      }
    });

    transformStream.readable
      .pipeTo(dnsQueryHandler)
      .catch(error => {
        this.log("DNS stream error: " + error);
      });

    const writer = transformStream.writable.getWriter();
    return { 
      write: (chunk) => writer.write(chunk) 
    };
  }
}

// GeoIP utilities
async function fetchGeoIPWithFallback(ip) {
  // Primary API: ip-api.io (HTTPS)
  try {
    const response = await fetch(`${API_ENDPOINTS.GEOIP_PRIMARY}${ip}`);
    if (response.ok) {
      const data = await response.json();
      if (data.ip || data.country_code) {
        return {
          ip: data.ip,
          country_name: data.country_name,
          city: data.city,
          country_code: data.country_code,
          isp: data.organisation || data.isp || data.org
        };
      }
    }
  } catch (error) {
    console.error(`Primary GeoIP API (ip-api.io) failed for IP ${ip}:`, error);
  }

  // Fallback API: ip-api.com (HTTP)
  try {
    const fallbackUrl = `${API_ENDPOINTS.GEOIP_FALLBACK}${ip}?fields=status,message,country,countryCode,city,isp,org,query`;
    const response = await fetch(fallbackUrl);
    if (response.ok) {
      const data = await response.json();
      if (data.status === 'success') {
        return {
          ip: data.query,
          country_name: data.country,
          city: data.city,
          country_code: data.countryCode,
          isp: data.isp || data.org
        };
      }
    }
  } catch (error) {
    console.error(`Fallback GeoIP API (ip-api.com) failed for IP ${ip}:`, error);
  }

  return null;
}

// HTML generation
async function generateHTML(currentUuid, hostName, proxyIP) {
  const protocol = decodeSecure(ENCODED_CONFIG.PROTOCOL);
  const networkType = decodeSecure(ENCODED_CONFIG.NETWORK);
  const baseUrl = `${protocol}://${currentUuid}@${hostName}:${VLESS_CONSTANTS.DEFAULT_PORT}`;
  const commonParams = `encryption=none&host=${hostName}&type=${networkType}&security=tls&sni=${hostName}`;
  const freedomConfig = `${baseUrl}?path=/api/v3&eh=Sec-WebSocket-Protocol&ed=2560&${commonParams}&fp=chrome&alpn=h3#${hostName}`;
  const dreamConfig = `${baseUrl}?path=%2FIndex%3Fed%3D2560&${commonParams}&fp=randomized&alpn=h2,http/1.1#${hostName}`;
  const clashMetaFullUrl = `clash://install-config?url=${encodeURIComponent(`https://revil-sub.pages.dev/sub/clash-meta?url=${encodeURIComponent(freedomConfig)}&remote_config=&udp=true&ss_uot=false&show_host=false&forced_ws0rtt=true`)}`;
  const nekoBoxImportUrl = `https://sahar-km.github.io/arcane/${btoa(freedomConfig)}`;

  const now = new Date();
  const timeString = now.toLocaleString("en-US", { 
    hour: "numeric", 
    minute: "numeric", 
    hour12: false, 
    day: "numeric", 
    month: "long" 
  });

  let html = HTML_TEMPLATE
    .replace(/<body(.*?)>/i, `<body$1 data-proxy-ip="${proxyIP}">`)
    .replace(/{{PROXY_IP}}/g, proxyIP)
    .replace(/{{LAST_UPDATED}}/g, timeString)
    .replace(/{{FREEDOM_CONFIG}}/g, freedomConfig)
    .replace(/{{DREAM_CONFIG}}/g, dreamConfig)
    .replace(/{{FREEDOM_CONFIG_ENCODED}}/g, encodeURIComponent(freedomConfig))
    .replace(/{{DREAM_CONFIG_ENCODED}}/g, encodeURIComponent(dreamConfig))
    .replace(/{{CLASH_META_URL}}/g, clashMetaFullUrl)
    .replace(/{{NEKOBOX_URL}}/g, nekoBoxImportUrl)
    .replace(/{{YEAR}}/g, now.getFullYear().toString());

  return html;
}

// Main export
export default {
  async fetch(request, env, ctx) {
    try {
      const config = new ProxyConfig(env);
      
      if (!config.isValidUserCode(config.userCode)) {
        throw new Error("Invalid user code");
      }

      const upgradeHeader = request.headers.get("Upgrade");
      const url = new URL(request.url);

      if (!upgradeHeader || upgradeHeader !== "websocket") {
        const requestHandler = new RequestHandler(config);
        return await requestHandler.handleStaticRoutes(request, url);
      } else {
        const wsHandler = new WebSocketStreamHandler(config);
        return await wsHandler.handle(request);
      }
    } catch (err) {
      console.error("Fetch error:", err);
      return new Response(err.toString(), { status: 500 });
    }
  }
};

// HTML template (unchanged from original)
const HTML_TEMPLATE = `<!doctype html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <title>VLESS Proxy Configuration</title>
  <link rel="preconnect" href="https://fonts.googleapis.com">
  <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
  <link
    href="https://fonts.googleapis.com/css2?family=Ibarra+Real+Nova:ital,wght@0,400..700;1,400..700&family=Fira+Code:wght@300..700&family=Inter:opsz,wght@14..32,100..900&family=Roboto+Mono:wght@100..700&display=swap"
    rel="stylesheet">
  <style>
    * {
      margin: 0;
      padding: 0;
      box-sizing: border-box;
    }

    @font-face {
      font-family: "Aldine 401 BT Web";
      src: url("https://pub-7a3b428c76aa411181a0f4dd7fa9064b.r2.dev/Aldine401_Mersedeh.woff2") format("woff2");
      font-weight: 400; font-style: normal; font-display: swap;
    }

    @font-face {
      font-family: "Styrene B LC";
      src: url("https://pub-7a3b428c76aa411181a0f4dd7fa9064b.r2.dev/StyreneBLC-Regular.woff2") format("woff2");
      font-weight: 400; font-style: normal; font-display: swap;
    }

    @font-face {
      font-family: "Styrene B LC";
      src: url("https://pub-7a3b428c76aa411181a0f4dd7fa9064b.r2.dev/StyreneBLC-Medium.woff2") format("woff2");
      font-weight: 500; font-style: normal; font-display: swap;
    }

    :root {
      --background-primary: #2a2421;
      --background-secondary: #35302c;
      --background-tertiary: #413b35;
      --border-color: #5a4f45;
      --border-color-hover: #766a5f;
      --text-primary: #e5dfd6;
      --text-secondary: #b3a89d;
      --text-accent: #ffffff;
      --accent-primary: #be9b7b;
      --accent-secondary: #d4b595;
      --accent-tertiary: #8d6e5c;
      --accent-primary-darker: #8a6f56;
      --button-text-primary: #2a2421;
      --button-text-secondary: var(--text-primary);
      --shadow-color: rgba(0, 0, 0, 0.35);
      --shadow-color-accent: rgba(190, 155, 123, 0.4);
      --border-radius: 8px;
      --transition-speed: 0.2s;
      --transition-speed-fast: 0.1s;
      --transition-speed-medium: 0.3s;
      --transition-speed-long: 0.6s;
      --status-success: #70b570;
      --status-error: #e05d44;
      --status-warning: #e0bc44;
      --status-info: #4f90c4;

      --serif: "Aldine 401 BT Web", "Times New Roman", Times, Georgia, ui-serif, serif;
      --sans-serif: "Styrene B LC", "Inter", -apple-system, BlinkMacSystemFont, "Helvetica Neue", Arial, "Noto Color Emoji", sans-serif;
      --mono-serif: "Fira Code", "Roboto Mono", Cantarell, Courier Prime, SFMono-Regular, monospace;
    }

    body {
      font-family: var(--sans-serif);
      font-size: 16px;
      font-weight: 400;
      font-style: normal;
      background-color: var(--background-primary);
      color: var(--text-primary);
      padding: 3rem;
      line-height: 1.5;
      -webkit-font-smoothing: antialiased;
      -moz-osx-font-smoothing: grayscale;
    }

    .container {
      max-width: 768;
      margin: 20px auto;
      padding: 0 12px;
      border-radius: var(--border-radius);
      box-shadow:
        0 6px 15px rgba(0, 0, 0, 0.2),
        0 0 25px 8px var(--shadow-color-accent);
      transition: box-shadow var(--transition-speed-medium) ease;
    }

    .container:hover {
      box-shadow:
        0 8px 20px rgba(0, 0, 0, 0.25),
        0 0 35px 10px var(--shadow-color-accent);
    }

    .header {
      text-align: center;
      margin-bottom: 40px;
      padding-top: 30px;
    }

    .header h1 {
      font-family: var(--serif);
      font-weight: 400;
      font-size: 2rem;
      color: var(--text-accent);
      margin-top: 0px;
      margin-bottom: 2px;
    }

    .header p {
      color: var(--text-secondary);
      font-size: 12px;
      font-weight: 400;
    }

    .config-card {
      background: var(--background-secondary);
      border-radius: var(--border-radius);
      padding: 20px;
      margin-bottom: 24px;
      border: 1px solid var(--border-color);
      transition:
        border-color var(--transition-speed) ease,
        box-shadow var(--transition-speed) ease;
    }

    .config-card:hover {
      border-color: var(--border-color-hover);
      box-shadow: 0 4px 8px var(--shadow-color);
    }

    .config-title {
      font-family: var(--serif);
      font-size: 22px;
      font-weight: 400;
      color: var(--accent-secondary);
      margin-bottom: 16px;
      padding-bottom: 12px;
      border-bottom: 1px solid var(--border-color);
      display: flex;
      align-items: center;
      justify-content: space-between;
    }

    .config-title .refresh-btn {
      position: relative;
      overflow: hidden;
      display: flex;
      align-items: center;
      gap: 4px;
      font-family: var(--serif);
      font-size: 12px;
      padding: 6px 12px;
      border-radius: 6px;
      color: var(--accent-secondary);
      background-color: var(--background-tertiary);
      border: 1px solid var(--border-color);
      cursor: pointer;

      transition:
        background-color var(--transition-speed) ease,
        border-color var(--transition-speed) ease,
        color var(--transition-speed) ease,
        transform var(--transition-speed) ease,
        box-shadow var(--transition-speed) ease;
    }

    .config-title .refresh-btn::before {
      content: "";
      position: absolute;
      top: 0;
      left: 0;
      width: 100%;
      height: 100%;
      background: linear-gradient(120deg, transparent, rgba(255, 255, 255, 0.2), transparent);
      transform: translateX(-100%);
      transition: transform var(--transition-speed-long) ease;
      z-index: -1;
    }

    .config-title .refresh-btn:hover {
      letter-spacing: 0.5px;
      font-weight: 600;
      background-color: #4d453e;
      color: var(--accent-primary);
      border-color: var(--border-color-hover);
      transform: translateY(-2px);
      box-shadow: 0 4px 8px var(--shadow-color);
    }

    .config-title .refresh-btn:hover::before {
      transform: translateX(100%);
    }

    .config-title .refresh-btn:active {
      transform: translateY(0px) scale(0.98);
      box-shadow: none;
    }

    .refresh-icon {
      width: 12px;
      height: 12px;
      stroke: currentColor;
    }

    .config-content {
      position: relative;
      background: var(--background-tertiary);
      border-radius: var(--border-radius);
      padding: 16px;
      margin-bottom: 20px;
      border: 1px solid var(--border-color);
    }

    .config-content pre {
      overflow-x: auto;
      font-family: var(--mono-serif);
      font-size: 12px;
      color: var(--text-primary);
      margin: 0;
      white-space: pre-wrap;
      word-break: break-all;
    }

    .button {
      display: inline-flex;
      align-items: center;
      justify-content: center;
      gap: 8px;
      padding: 8px 16px;
      border-radius: var(--border-radius);
      font-size: 13px;
      font-weight: 500;
      cursor: pointer;
      border: 1px solid var(--border-color);
      background-color: var(--background-tertiary);
      color: var(--button-text-secondary);
      transition:
        background-color var(--transition-speed) ease,
        border-color var(--transition-speed) ease,
        color var(--transition-speed) ease,
        transform var(--transition-speed) ease,
        box-shadow var(--transition-speed) ease;
      -webkit-tap-highlight-color: transparent;
      touch-action: manipulation;
      text-decoration: none;
      overflow: hidden;
      z-index: 1;
    }

    .button:focus-visible {
      outline: 2px solid var(--accent-primary);
      outline-offset: 2px;
    }

    .button:disabled {
      opacity: 0.6;
      cursor: not-allowed;
      transform: none;
      box-shadow: none;
      transition: opacity var(--transition-speed) ease;
    }

    .button:not(.copy-buttons):not(.client-btn):hover {
      background-color: #4d453e;
      border-color: var(--border-color-hover);
      transform: translateY(-1px);
      box-shadow: 0 2px 4px var(--shadow-color);
    }

    .button:not(.copy-buttons):not(.client-btn):active {
      transform: translateY(0px) scale(0.98);
      box-shadow: none;
    }

    .copy-buttons {
      position: relative;
      display: flex;
      gap: 4px;
      overflow: hidden;
      align-self: center;
      font-family: var(--serif);
      font-size: 12px;
      padding: 6px 12px;
      border-radius: 6px;
      color: var(--accent-secondary);
      border: 1px solid var(--border-color);
      transition:
        background-color var(--transition-speed) ease,
        border-color var(--transition-speed) ease,
        color var(--transition-speed) ease,
        transform var(--transition-speed) ease,
        box-shadow var(--transition-speed) ease;
    }

    .copy-buttons::before,
    .client-btn::before {
      content: "";
      position: absolute;
      top: 0;
      left: 0;
      width: 100%;
      height: 100%;
      background: linear-gradient(120deg, transparent, rgba(255, 255, 255, 0.2), transparent);
      transform: translateX(-100%);
      transition: transform var(--transition-speed-long) ease;
      z-index: -1;
    }

    .copy-buttons:hover::before,
    .client-btn:hover::before {
      transform: translateX(100%);
    }

    .copy-buttons:hover {
      background-color: #4d453e;
      letter-spacing: 0.5px;
      font-weight: 600;
      border-color: var(--border-color-hover);
      transform: translateY(-2px);
      box-shadow: 0 4px 8px var(--shadow-color);
    }

    .copy-buttons:active {
      transform: translateY(0px) scale(0.98);
      box-shadow: none;
    }

    .copy-icon {
      width: 12px;
      height: 12px;
      stroke: currentColor;
    }

    .client-buttons {
      display: grid;
      grid-template-columns: repeat(auto-fill, minmax(300px, 1fr));
      gap: 12px;
      margin-top: 16px;
    }

    .client-btn {
      width: 100%;
      background-color: var(--accent-primary);
      color: var(--background-tertiary);
      border-radius: 6px;
      border-color: var(--accent-primary-darker);
      position: relative;
      overflow: hidden;
      transition: all 0.3s cubic-bezier(0.2, 0.8, 0.2, 1);
      box-shadow: 0 2px 5px rgba(0, 0, 0, 0.15);
    }

    .client-btn::before {
      left: -100%;
      transition: transform 0.6s ease;
      z-index: 1;
    }

    .client-btn::after {
      content: "";
      position: absolute;
      bottom: -5px;
      left: 0;
      width: 100%;
      height: 5px;
      background: linear-gradient(90deg, var(--accent-tertiary), var(--accent-secondary));
      opacity: 0;
      transition: all 0.3s ease;
      z-index: 0;
    }

    .client-btn:hover {
      text-transform: uppercase;
      letter-spacing: 0.3px;
      transform: translateY(-3px);
      background-color: var(--accent-secondary);
      color: var(--button-text-primary);
      box-shadow: 0 5px 15px rgba(190, 155, 123, 0.5);
      border-color: var(--accent-secondary);
    }

    .client-btn:hover::before {
      transform: translateX(100%);
    }

    .client-btn:hover::after {
      opacity: 1;
      bottom: 0;
    }

    .client-btn:active {
      transform: translateY(0) scale(0.98);
      box-shadow: 0 2px 3px rgba(0, 0, 0, 0.2);
      background-color: var(--accent-primary-darker);
    }

    .client-btn .client-icon {
      position: relative;
      z-index: 2;
      transition: transform 0.3s ease;
    }

    .client-btn:hover .client-icon {
      transform: rotate(15deg) scale(1.1);
    }

    .client-btn .button-text {
      position: relative;
      z-index: 2;
      transition: letter-spacing 0.3s ease;
    }

    .client-btn:hover .button-text { letter-spacing: 0.5px; }
    .client-icon { width: 18px; height: 18px; border-radius: 6px; background-color: var(--background-secondary); display: flex; align-items: center; justify-content: center; flex-shrink: 0; }
    .client-icon svg { width: 14px; height: 14px; fill: var(--accent-secondary); }

    .button.copied { background-color: var(--accent-secondary) !important; color: var(--background-tertiary) !important; }
    .button.error { background-color: #c74a3b !important; color: var(--text-accent) !important; }

    .footer { text-align: center; margin-top: 20px; padding-bottom: 40px; color: var(--text-secondary); font-size: 12px; }
    .footer p { margin-bottom: 0px; }

    ::-webkit-scrollbar { width: 8px; height: 8px; }
    ::-webkit-scrollbar-track { background: var(--background-primary); border-radius: 4px; }
    ::-webkit-scrollbar-thumb { background: var(--border-color); border-radius: 4px; border: 2px solid var(--background-primary); }
    ::-webkit-scrollbar-thumb:hover { background: var(--border-color-hover); }
    * { scrollbar-width: thin; scrollbar-color: var(--border-color) var(--background-primary); }

    .ip-info-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(230px, 1fr)); gap: 24px; }
    .ip-info-section { background-color: var(--background-tertiary); border-radius: var(--border-radius); padding: 16px; border: 1px solid var(--border-color); display: flex; flex-direction: column; gap: 20px; }
    .ip-info-header { display: flex; align-items: center; gap: 10px; border-bottom: 1px solid var(--border-color); padding-bottom: 10px; }
    .ip-info-header svg { width: 20px; height: 20px; stroke: var(--accent-secondary); }
    .ip-info-header h3 { font-family: var(--serif); font-size: 18px; font-weight: 400; color: var(--accent-secondary); margin: 0; }
    .ip-info-content { display: flex; flex-direction: column; gap: 10px; }
    .ip-info-item { display: flex; flex-direction: column; gap: 2px; }
    .ip-info-item .label { font-size: 11px; color: var(--text-secondary); text-transform: uppercase; letter-spacing: 0.5px; }
    .ip-info-item .value { font-size: 14px; color: var(--text-primary); word-break: break-all; line-height: 1.4; }

    .badge { display: inline-flex; align-items: center; justify-content: center; padding: 3px 8px; border-radius: 12px; font-size: 11px; font-weight: 500; text-transform: uppercase; letter-spacing: 0.5px; }
    .badge-yes { background-color: rgba(112, 181, 112, 0.15); color: var(--status-success); border: 1px solid rgba(112, 181, 112, 0.3); }
    .badge-no { background-color: rgba(224, 93, 68, 0.15); color: var(--status-error); border: 1px solid rgba(224, 93, 68, 0.3); }
    .badge-neutral { background-color: rgba(79, 144, 196, 0.15); color: var(--status-info); border: 1px solid rgba(79, 144, 196, 0.3); }
    .badge-warning { background-color: rgba(224, 188, 68, 0.15); color: var(--status-warning); border: 1px solid rgba(224, 188, 68, 0.3); }

    .skeleton { display: block; background: linear-gradient(90deg, var(--background-tertiary) 25%, var(--background-secondary) 50%, var(--background-tertiary) 75%); background-size: 200% 100%; animation: loading 1.5s infinite; border-radius: 4px; height: 16px; }
    @keyframes loading { 0% { background-position: 200% 0; } 100% { background-position: -200% 0; } }
    .country-flag { display: inline-block; width: 18px; height: auto; max-height: 14px; margin-right: 6px; vertical-align: middle; border-radius: 2px; }

     @media (max-width: 768px) {
      body { padding: 20px; }
      .container { padding: 0 14px; width: min(100%, 768px); }
      .ip-info-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(170px, 1fr)); gap: 18px; }
      .header h1 { font-size: 1.8rem; }
      .header p { font-size: 0.7rem }
      .ip-info-section { padding: 14px; gap: 18px; }
      .ip-info-header h3 { font-size: 16px; }
      .ip-info-header { gap: 8px; }
      .ip-info-content { gap: 8px; }
      .ip-info-item .label { font-size: 11px; }
      .ip-info-item .value { font-size: 13px; }
      .config-card { padding: 16px; }
      .config-title { font-size: 18px; }
      .config-title .refresh-btn { font-size: 11px; }
      .config-content pre { font-size: 12px; }
      .client-buttons { grid-template-columns: repeat(auto-fill, minmax(260px, 1fr)); }
      .button { font-size: 12px; }
       .copy-buttons { font-size: 11px; }
    }

    @media (max-width: 480px) {
      body { padding: 16px; }
      .container { padding: 0 12px; width: min(100%, 390px); }
      .header h1 { font-size: 20px; }
      .header p { font-size: 8px; }
      .ip-info-section { padding: 14px; gap: 16px; }
      .ip-info-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 16px; }
      .ip-info-header h3 { font-size: 14px; }
      .ip-info-header { gap: 6px; }
      .ip-info-content { gap: 6px; }
      .ip-info-header svg { width: 18px; height: 18px; }
      .ip-info-item .label { font-size: 9px; }
      .ip-info-item .value { font-size: 11px; }
      .badge { padding: 2px 6px; font-size: 10px; border-radius: 10px; }
      .config-card { padding: 10px; }
      .config-title { font-size: 16px; }
      .config-title .refresh-btn { font-size: 10px; }
      .config-content { padding: 12px; }
      .config-content pre { font-size: 10px; }
      .client-buttons { grid-template-columns: repeat(auto-fill, minmax(200px, 1fr)); }
      .button { padding: 4px 8px; font-size: 11px; }
      .copy-buttons { font-size: 10px; }
      .footer { font-size: 10px; }
    }

    @media (max-width: 359px) {
      body { padding: 12px; font-size: 14px; }
      .container { max-width: 100%; padding: 8px; }
      .header h1 { font-size: 16px; }
      .header p { font-size: 6px; }
      .ip-info-section { padding: 12px; gap: 12px; }
      .ip-info-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(150px, 1fr)); gap: 10px; }
      .ip-info-header h3 { font-size: 13px; }
      .ip-info-header { gap: 4px; }
      .ip-info-content { gap: 4px; }
      .ip-info-header svg { width: 16px; height: 16px; }
      .ip-info-item .label { font-size: 8px; }
      .ip-info-item .value { font-size: 10px; }
      .badge { padding: 1px 4px; font-size: 9px; border-radius: 8px; }
      .config-card { padding: 8px; }
      .config-title { font-size: 13px; }
      .config-title .refresh-btn { font-size: 9px; }
      .config-content { padding: 8px; }
      .config-content pre { font-size: 8px; }
      .client-buttons { grid-template-columns: repeat(auto-fill, minmax(150px, 1fr)); }
      .button { padding: 3px 6px; font-size: 10px; }
      .copy-buttons { font-size: 9px; }
      .footer { font-size: 8px; }
    }

    @media (min-width: 360px) { .container { max-width: 95%; } }
    @media (min-width: 480px) { .container { max-width: 90%; } }
    @media (min-width: 640px) { .container { max-width: 600px; } }
    @media (min-width: 768px) { .container { max-width: 720px; } }
    @media (min-width: 1024px) { .container { max-width: 800px; } }
  </style>
</head>
<body data-proxy-ip="{{PROXY_IP}}">
  <div class="container">
    <div class="header">
      <h1>VLESS Proxy Configuration</h1>
      <p>Copy the configuration or import directly into your client</p>
    </div>

    <div class="config-card">
      <div class="config-title">
        <span>Network Information</span>
        <button id="refresh-ip-info" class="refresh-btn" aria-label="Refresh IP information">
          <svg class="refresh-icon" xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none"
            stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
            <path d="M21.5 2v6h-6M2.5 22v-6h6M2 11.5a10 10 0 0 1 18.8-4.3M22 12.5a10 10 0 0 1-18.8 4.2" />
          </svg>
          Refresh
        </button>
      </div>

      <div class="ip-info-grid">
        <div class="ip-info-section">
          <div class="ip-info-header">
            <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
              <path d="M15.5 2H8.6c-.4 0-.8.2-1.1.5-.3.3-.5.7-.5 1.1v16.8c0 .4.2.8.5 1.1.3.3.7.5 1.1.5h6.9c.4 0 .8-.2 1.1-.5.3-.3.5-.7.5-1.1V3.6c0-.4-.2-.8-.5-1.1-.3-.3-.7-.5-1.1-.5z"/>
              <circle cx="12" cy="18" r="1"/>
            </svg>
            <h3>Proxy Server</h3>
          </div>
          <div class="ip-info-content">
            <div class="ip-info-item">
              <span class="label">Proxy Host</span>
              <span class="value" id="proxy-host"><span class="skeleton" style="width: 150px;"></span></span>
            </div>
            <div class="ip-info-item">
              <span class="label">IP Address</span>
              <span class="value" id="proxy-ip"><span class="skeleton" style="width: 120px;"></span></span>
            </div>
            <div class="ip-info-item">
              <span class="label">Location</span>
              <span class="value" id="proxy-location"><span class="skeleton" style="width: 100px;"></span></span>
            </div>
            <div class="ip-info-item">
              <span class="label">ISP Provider</span>
              <span class="value" id="proxy-isp"><span class="skeleton" style="width: 140px;"></span></span>
            </div>
          </div>
        </div>

        <div class="ip-info-section">
          <div class="ip-info-header">
            <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
              <path d="M20 16V7a2 2 0 0 0-2-2H6a2 2 0 0 0-2 2v9m16 0H4m16 0 1.28 2.55a1 1 0 0 1-.9 1.45H3.62a1 1 0 0 1-.9-1.45L4 16"/>
            </svg>
            <h3>Your Connection</h3>
          </div>
          <div class="ip-info-content">
            <div class="ip-info-item">
              <span class="label">Your IP</span>
              <span class="value" id="client-ip"><span class="skeleton" style="width: 110px;"></span></span>
            </div>
            <div class="ip-info-item">
              <span class="label">Location</span>
              <span class="value" id="client-location"><span class="skeleton" style="width: 90px;"></span></span>
            </div>
            <div class="ip-info-item">
              <span class="label">ISP Provider</span>
              <span class="value" id="client-isp"><span class="skeleton" style="width: 130px;"></span></span>
            </div>
            <div class="ip-info-item">
              <span class="label">Risk Score</span>
              <span class="value" id="client-proxy">
                <span class="skeleton" style="width: 100px;"></span>
              </span>
            </div>
          </div>
        </div>
      </div>
    </div>

    <div class="config-card">
      <div class="config-title">
        <span>Xray Core Clients</span>
        <button class="button copy-buttons" onclick="copyToClipboard(this, '{{DREAM_CONFIG}}')">
          <svg class="copy-icon" xmlns="http://www.w3.org/2000/svg" width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
            <rect x="9" y="9" width="13" height="13" rx="2" ry="2"></rect>
            <path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"></path>
          </svg>
          Copy
        </button>
      </div>
      <div class="config-content">
        <pre id="xray-config">{{DREAM_CONFIG}}</pre>
      </div>
      <div class="client-buttons">
        <a href="hiddify://install-config?url={{FREEDOM_CONFIG_ENCODED}}" class="button client-btn">
          <span class="client-icon"><svg viewBox="0 0 24 24"><path d="M12 2L2 7l10 5 10-5-10-5zM2 17l10 5 10-5M2 12l10 5 10-5" /></svg></span>
          <span class="button-text">Import to Hiddify</span>
        </a>
        <a href="v2rayng://install-config?url={{DREAM_CONFIG_ENCODED}}" class="button client-btn">
          <span class="client-icon"><svg viewBox="0 0 24 24"><path d="M12 2L4 5v6c0 5.5 3.5 10.7 8 12.3 4.5-1.6 8-6.8 8-12.3V5l-8-3z" /></svg></span>
          <span class="button-text">Import to V2rayNG</span>
        </a>
      </div>
    </div>

    <div class="config-card">
      <div class="config-title">
        <span>Sing-Box Core Clients</span>
        <button class="button copy-buttons" onclick="copyToClipboard(this, '{{FREEDOM_CONFIG}}')">
          <svg class="copy-icon" xmlns="http://www.w3.org/2000/svg" width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
            <rect x="9" y="9" width="13" height="13" rx="2" ry="2"></rect>
            <path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"></path>
          </svg>
          Copy
        </button>
      </div>
      <div class="config-content">
        <pre id="singbox-config">{{FREEDOM_CONFIG}}</pre>
      </div>
      <div class="client-buttons">
        <a href="{{CLASH_META_URL}}" class="button client-btn">
          <span class="client-icon"><svg viewBox="0 0 24 24"><path d="M12 2C6.48 2 2 6.48 2 12s4.48 10 10 10 10-4.48 10-10S17.52 2 12 2zm-1 17.93c-3.95-.49-7-3.85-7-7.93 0-.62.08-1.21.21-1.79L9 15v1c0 1.1.9 2 2 2v1.93zm6.9-2.54c-.26-.81-1-1.39-1.9-1.39h-1v-3c0-.55-.45-1-1-1H8v-2h2c.55 0 1-.45 1-1V7h2c1.1 0 2-.9 2-2v-.41c2.93 1.19 5 4.06 5 7.41 0 2.08-.8 3.97-2.1 5.39z" /></svg></span>
          <span class="button-text">Import to Clash Meta</span>
        </a>
        <a href="{{NEKOBOX_URL}}" class="button client-btn">
          <span class="client-icon"><svg viewBox="0 0 24 24"><path d="M20,8h-3V6c0-1.1-0.9-2-2-2H9C7.9,4,7,4.9,7,6v2H4C2.9,8,2,8.9,2,10v9c0,1.1,0.9,2,2,2h16c1.1,0,2-0.9,2-2v-9 C22,8.9,21.1,8,20,8z M9,6h6v2H9V6z M20,19H4v-2h16V19z M20,15H4v-5h3v1c0,0.55,0.45,1,1,1h1.5c0.28,0,0.5-0.22,0.5-0.5v-0.5h4v0.5 c0,0.28,0.22,0.5,0.5,0.5H16c0.55,0,1-0.45,1-1v-1h3V15z" /><circle cx="8.5" cy="13.5" r="1" /><circle cx="15.5" cy="13.5" r="1" /><path d="M12,15.5c-0.55,0-1-0.45-1-1h2C13,15.05,12.55,15.5,12,15.5z" /></svg></span>
          <span class="button-text">Import to NekoBox</span>
        </a>
      </div>
    </div>

    <div class="footer">
      <p>© <span id="current-year">{{YEAR}}</span> REvil - All Rights Reserved</p>
      <p>Secure. Private. Fast.</p>
    </div>
  </div>

  <script>
    function copyToClipboard(button, text) {
      const originalHTML = button.innerHTML;

      navigator.clipboard.writeText(text).then(() => {
        button.innerHTML = `
          <svg class="copy-icon" xmlns="http://www.w3.org/2000/svg" width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
            <rect x="9" y="9" width="13" height="13" rx="2" ry="2"></rect>
            <path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"></path>
          </svg>
          Copied!
        `;
        button.classList.add("copied");
        button.disabled = true;

        setTimeout(() => {
          button.innerHTML = originalHTML;
          button.classList.remove("copied");
          button.disabled = false;
        }, 1200);
      }).catch(err => {
        console.error("Failed to copy text: ", err);
        const originalHTMLError = button.innerHTML;

        button.innerHTML = `
          <svg class="copy-icon" xmlns="http://www.w3.org/2000/svg" width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
            <rect x="9" y="9" width="13" height="13" rx="2" ry="2"></rect>
            <path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"></path>
          </svg>
          Error
        `;
        button.classList.add("error");
        button.disabled = true;

        setTimeout(() => {
          button.innerHTML = originalHTMLError;
          button.classList.remove("error");
          button.disabled = false;
        }, 1500);
      });
    }

    async function fetchClientPublicIP() {
      try {
        const response = await fetch('/api/ip');
        if (!response.ok) {
          throw new Error(`HTTP error! status: ${response.status}`);
        }
        const data = await response.json();
        return data.ip;
      } catch (error) {
        console.error('Error fetching client IP from worker:', error);
        return null;
      }
    }

    async function fetchScamalyticsClientInfo(clientIp) {
      if (!clientIp) return null;
      try {
        const workerLookupUrl = `/scamalytics-lookup?ip=${encodeURIComponent(clientIp)}`;
        const response = await fetch(workerLookupUrl);

        if (!response.ok) {
          let errorDetail = `Worker request failed! status: ${response.status}`;
          try {
            const errorData = await response.json();
             if (errorData && errorData.error) {
                errorDetail = errorData.error;
                if(errorData.details) errorDetail += ` Details: ${errorData.details}`;
            } else if (errorData && errorData.scamalytics && errorData.scamalytics.error) {
                 errorDetail = errorData.scamalytics.error;
            } else if (response.statusText) {
                errorDetail += ` - ${response.statusText}`;
            }
          } catch (e) {
            errorDetail += ` - ${await response.text()}`;
          }
          throw new Error(errorDetail);
        }
        const data = await response.json();
        if (data.scamalytics && data.scamalytics.status === 'error') {
            throw new Error(data.scamalytics.error || 'Scamalytics API error via Worker');
        }
        if (data.error && !data.scamalytics) {
            throw new Error(data.error);
        }
        return data;
      } catch (error) {
        console.error('Error fetching from Scamalytics via Worker:', error);
        return null;
      }
    }

    function updateScamalyticsClientDisplay(data) {
      const prefix = 'client';
      if (!data || !data.scamalytics || data.scamalytics.status !== 'ok') {
        // Don't show error here, as geo data might come from the other source.
        // Only update the risk score part.
        const proxyElement = document.getElementById(`${prefix}-proxy`);
        if(proxyElement) proxyElement.innerHTML = `<span class="badge badge-neutral">N/A</span>`;
        return;
      }

      const sa = data.scamalytics;
      const proxyElement = document.getElementById(`${prefix}-proxy`);

      if (proxyElement) {
        const score = sa.scamalytics_score;
        const risk = sa.scamalytics_risk;
        let riskText = "Unknown";
        let badgeClass = "badge-neutral";

        if (risk !== undefined && score !== undefined && risk !== null && score !== null) {
            riskText = `${score} - ${risk.charAt(0).toUpperCase() + risk.slice(1)}`;
            switch (risk.toLowerCase()) {
                case "low": badgeClass = "badge-yes"; break;
                case "medium": badgeClass = "badge-warning"; break;
                case "high": badgeClass = "badge-no"; break;
                case "very high": badgeClass = "badge-no"; break;
                default:
                    badgeClass = "badge-neutral";
                    riskText = `Score ${score} - ${risk || 'Status Unknown'}`;
                    break;
            }
        } else if (score !== undefined && score !== null) {
            riskText = `Score ${score} - N/A`;
        } else if (risk) {
            riskText = risk.charAt(0).toUpperCase() + risk.slice(1);
             switch (risk.toLowerCase()) {
                case "low": badgeClass = "badge-yes"; break;
                case "medium": badgeClass = "badge-warning"; break;
                case "high": case "very high": badgeClass = "badge-no"; break;
                default: badgeClass = "badge-neutral"; riskText="Status Unknown"; break;
            }
        }
        proxyElement.innerHTML = `<span class="badge ${badgeClass}">${riskText}</span>`;
      }
    }

    function updateProxyDisplay(geo, prefix, originalHost) {
      const hostElement = document.getElementById(`${prefix}-host`);
      if (hostElement) {
        hostElement.textContent = originalHost || "N/A";
      }

      const ipElement = document.getElementById(`${prefix}-ip`);
      const locationElement = document.getElementById(`${prefix}-location`);
      const ispElement = document.getElementById(`${prefix}-isp`);

      if (!geo) {
        if (ipElement) ipElement.textContent = "N/A";
        if (locationElement) locationElement.innerHTML = "N/A";
        if (ispElement) ispElement.textContent = "N/A";
        return;
      }

      if (ipElement) ipElement.textContent = geo.ip || "N/A";

      if (locationElement) {
        const city = geo.city || '';
        const countryName = geo.country_name || '';
        const countryCode = geo.country_code ? geo.country_code.toLowerCase() : '';
        let flagElementHtml = '';

        if (countryCode) {
            flagElementHtml = `<img src="https://flagcdn.com/w20/${countryCode}.png" srcset="https://flagcdn.com/w40/${countryCode}.png 2x" alt="${geo.country_code || 'flag'}" class="country-flag"> `;
        }

        let textPart = '';
        if (city && countryName) textPart = `${city}, ${countryName}`;
        else if (countryName) textPart = countryName;
        else if (city) textPart = city;

        let locationText = 'N/A';
        if (flagElementHtml.trim() || textPart.trim()) {
            locationText = `${flagElementHtml}${textPart}`.trim();
        }
        locationElement.innerHTML = locationText || "N/A";
      }
      if (ispElement) {
        ispElement.textContent = geo.isp || 'N/A';
      }
    }

    async function fetchGeoIpInfo(ip) {
      try {
        const response = await fetch(`/api/geoip/${ip}`);
        if (!response.ok) {
            const errorText = await response.text();
            throw new Error(`HTTP error! status: ${response.status}, message: ${errorText}`);
        }
        return await response.json();
      } catch (error) {
        console.error('GeoIP API Error (via worker):', error);
        return null;
      }
    }

    function showError(prefix, message = "Could not load data", originalHostForProxy = null) {
      const errorMessage = "N/A";
      if (prefix === 'proxy') {
        const hostElement = document.getElementById('proxy-host');
        const ipElement = document.getElementById('proxy-ip');
        const locationElement = document.getElementById('proxy-location');
        const ispElement = document.getElementById('proxy-isp');
        if (hostElement) hostElement.textContent = originalHostForProxy || errorMessage;
        if (ipElement) ipElement.textContent = errorMessage;
        if (locationElement) locationElement.innerHTML = errorMessage;
        if (ispElement) ispElement.textContent = errorMessage;
      } else if (prefix === 'client') {
        const ipElement = document.getElementById('client-ip');
        const locationElement = document.getElementById('client-location');
        const ispElement = document.getElementById('client-isp');
        const riskScoreElement = document.getElementById('client-proxy');
        if (ipElement) ipElement.textContent = errorMessage;
        if (locationElement) locationElement.innerHTML = errorMessage;
        if (ispElement) ispElement.textContent = errorMessage;
        if (riskScoreElement) riskScoreElement.innerHTML = `<span class="badge badge-neutral">N/A</span>`;
      }
      console.warn(`${prefix} data loading failed: ${message}`);
    }

    async function loadNetworkInfo() {
        // --- Load Client Info ---
        const clientIp = await fetchClientPublicIP();
        if (clientIp) {
            document.getElementById('client-ip').textContent = clientIp;

            const clientGeoData = await fetchGeoIpInfo(clientIp);
            if(clientGeoData) {
                const clientLocationEl = document.getElementById('client-location');
                const clientIspEl = document.getElementById('client-isp');

                const city = clientGeoData.city || '';
                const countryName = clientGeoData.country_name || '';
                const countryCode = clientGeoData.country_code ? clientGeoData.country_code.toLowerCase() : '';
                let flagHtml = countryCode ? `<img src="https://flagcdn.com/w20/${countryCode}.png" srcset="https://flagcdn.com/w40/${countryCode}.png 2x" alt="${clientGeoData.country_code}" class="country-flag"> ` : '';

                let locationText = 'N/A';
                if (city && countryName) locationText = `${city}, ${countryName}`;
                else if (countryName) locationText = countryName;
                else if (city) locationText = city;

                clientLocationEl.innerHTML = `${flagHtml}${locationText}`.trim();
                clientIspEl.textContent = clientGeoData.isp || 'N/A';
            } else {
                showError('client', 'Could not load client geo data.');
            }

            const scamalyticsData = await fetchScamalyticsClientInfo(clientIp);
            updateScamalyticsClientDisplay(scamalyticsData);

        } else {
            showError('client', 'Could not determine your IP address.');
        }

        // --- Load Proxy Server Info ---
        const proxyDomainOrIp = document.body.getAttribute('data-proxy-ip');
        let resolvedProxyIp = proxyDomainOrIp;
        const proxyHostVal = (proxyDomainOrIp && proxyDomainOrIp.toLowerCase() !== "null" && proxyDomainOrIp.trim() !== "") ? proxyDomainOrIp : "N/A";

        if (proxyHostVal !== "N/A") {
            if (!/^\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}$/.test(proxyDomainOrIp)) {
                try {
                    const dnsRes = await fetch(`https://dns.google/resolve?name=${encodeURIComponent(proxyDomainOrIp)}&type=A`);
                    if (dnsRes.ok) {
                        const dnsData = await dnsRes.json();
                        if (dnsData.Answer && dnsData.Answer.length > 0) {
                            const ipAnswer = dnsData.Answer.find(a => a.type === 1);
                            if (ipAnswer) resolvedProxyIp = ipAnswer.data;
                        }
                    }
                } catch (e) {
                    console.error('DNS resolution for proxy failed:', e);
                }
            }

            const proxyGeoData = await fetchGeoIpInfo(resolvedProxyIp);
            if (proxyGeoData) {
                updateProxyDisplay(proxyGeoData, 'proxy', proxyHostVal);
            } else {
                showError('proxy', `Could not load proxy geo data for ${resolvedProxyIp}.`, proxyHostVal);
            }
        } else {
            showError('proxy', 'Proxy Host not available', "N/A");
        }
    }

    // Refresh button functionality
    document.getElementById('refresh-ip-info')?.addEventListener('click', function() {
      const button = this;
      const icon = button.querySelector('.refresh-icon');
      button.disabled = true;
      if (icon) icon.style.animation = 'spin 1s linear infinite';

      const resetToSkeleton = (prefix) => {
        const elementsToReset = ['ip', 'location', 'isp'];
        if (prefix === 'proxy') elementsToReset.push('host');
        if (prefix === 'client') elementsToReset.push('proxy');

        elementsToReset.forEach(elemKey => {
          const element = document.getElementById(`${prefix}-${elemKey}`);
          if (element) {
            let skeletonWidth = "100px";
            if (elemKey === 'isp') skeletonWidth = "130px";
            else if (elemKey === 'location') skeletonWidth = "110px";
            else if (elemKey === 'ip') skeletonWidth = "120px";
            else if (elemKey === 'host' && prefix === 'proxy') skeletonWidth = "150px";
            else if (elemKey === 'proxy' && prefix === 'client') skeletonWidth = "100px";
            element.innerHTML = `<span class="skeleton" style="width: ${skeletonWidth};"></span>`;
          }
        });
      };

      resetToSkeleton('proxy');
      resetToSkeleton('client');
      loadNetworkInfo().finally(() => setTimeout(() => {
        button.disabled = false; if (icon) icon.style.animation = '';
      }, 1000));
    });

    const style = document.createElement('style');
    style.textContent = `@keyframes spin { from { transform: rotate(0deg); } to { transform: rotate(360deg); } }`;
    document.head.appendChild(style);

    document.addEventListener('DOMContentLoaded', () => {
      console.log('Page loaded, initializing network info...');
      loadNetworkInfo();
    });
</script>
</body>
</html>
`.replace(/\\/g, "\\\\").replace(/`/g, "\\`");
