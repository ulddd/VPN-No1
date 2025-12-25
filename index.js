const os = require('os');
const http = require('http');
const fs = require('fs');
const axios = require('axios');
const net = require('net');
const path = require('path');
const crypto = require('crypto');
const { Buffer } = require('buffer');
const { WebSocket, createWebSocketStream } = require('ws');

// --- 安全与基础配置 ---
const UUID = process.env.UUID || '6cf627de-147b-43dd-a50e-61ce1db2ecb3'; 
const DOMAIN = process.env.DOMAIN || '';           // 填入你的 Hugging Face 或 Worker 域名
const WSPATH = process.env.WSPATH || UUID.slice(0, 8); // 默认路径为 UUID 前 8 位
const SUB_PATH = process.env.SUB_PATH || 'sub';    // 订阅路径
const NAME = process.env.NAME || 'WildGuard-Node'; // 节点名称
const PORT = process.env.PORT || 7860;             // 适配 Hugging Face 端口

let ISP = '';
const GetISP = async () => {
  try {
    const res = await axios.get('https://api.ip.sb/geoip');
    ISP = `${res.data.country_code}-${res.data.isp}`.replace(/ /g, '_');
  } catch (e) {
    ISP = 'Cloud-Server';
  }
}
GetISP();

// --- HTTP 服务：处理伪装页与订阅 ---
const httpServer = http.createServer((req, res) => {
  if (req.url === '/') {
    const filePath = path.join(__dirname, 'index.html');
    fs.readFile(filePath, 'utf8', (err, content) => {
      res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
      res.end(err ? 'Service Running' : content);
    });
  } else if (req.url === `/${SUB_PATH}`) {
    const namePart = NAME ? `${NAME}-${ISP}` : ISP;
    const vlessURL = `vless://${UUID}@${DOMAIN}:443?encryption=none&security=tls&sni=${DOMAIN}&fp=chrome&type=ws&host=${DOMAIN}&path=%2F${WSPATH}#${namePart}`;
    const trojanURL = `trojan://${UUID}@${DOMAIN}:443?security=tls&sni=${DOMAIN}&fp=chrome&type=ws&host=${DOMAIN}&path=%2F${WSPATH}#${namePart}`;
    
    const subscription = Buffer.from(vlessURL + '\n' + trojanURL).toString('base64');
    res.writeHead(200, { 'Content-Type': 'text/plain; charset=utf-8' });
    res.end(subscription + '\n');
  } else {
    res.writeHead(404);
    res.end();
  }
});

// --- WebSocket 代理逻辑 (含加固错误处理) ---
const wss = new WebSocket.Server({ server: httpServer });
const cleanUuid = UUID.replace(/-/g, "");

function resolveHost(host) {
  return new Promise((resolve, reject) => {
    if (/^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$/.test(host)) return resolve(host);
    axios.get(`https://dns.google/resolve?name=${encodeURIComponent(host)}&type=A`, {
      timeout: 5000,
      headers: { 'Accept': 'application/dns-json' }
    }).then(res => {
      const ip = res.data.Answer?.find(record => record.type === 1);
      ip ? resolve(ip.data) : reject();
    }).catch(() => reject());
  });
}

wss.on('connection', (ws) => {
  ws.once('message', msg => {
    const isVless = msg[0] === 0 && msg.length > 17;
    const duplex = createWebSocketStream(ws);

    // 统一的流错误处理，防止 readyState 2 崩溃
    duplex.on('error', () => { 
        if (ws.readyState === WebSocket.OPEN) ws.close();
        duplex.destroy();
    });

    if (isVless) {
      const id = msg.slice(1, 17);
      if (!id.every((v, i) => v == parseInt(cleanUuid.substr(i * 2, 2), 16))) return ws.close();
      
      let i = msg.slice(17, 18).readUInt8() + 19;
      const port = msg.slice(i, i += 2).readUInt16BE(0);
      const ATYP = msg.slice(i, i += 1).readUInt8();
      const host = ATYP == 1 ? msg.slice(i, i += 4).join('.') :
        (ATYP == 2 ? new TextDecoder().decode(msg.slice(i + 1, i += 1 + msg.slice(i, i + 1).readUInt8())) : 'localhost');

      ws.send(new Uint8Array([0, 0]));

      resolveHost(host).then(ip => {
        const socket = net.connect({ host: ip, port }, function() {
          this.write(msg.slice(i));
          duplex.pipe(this).on('error', () => {}).pipe(duplex);
        });
        socket.on('error', () => { duplex.destroy(); });
      }).catch(() => ws.close());

    } else {
      // Trojan 处理逻辑
      try {
        const receivedHash = msg.slice(0, 56).toString();
        const expectedHash = crypto.createHash('sha224').update(UUID).digest('hex');
        if (receivedHash !== expectedHash) return ws.close();
        
        // 简化后的转发，增加基础防护
        const socket = net.connect({ host: 'localhost', port: 80 }, () => {
           duplex.pipe(socket).on('error', () => {}).pipe(duplex);
        });
        socket.on('error', () => { duplex.destroy(); });
      } catch (e) { ws.close(); }
    }
  });

  ws.on('error', () => {}); // 捕获静默错误
});

// --- 启动服务 ---
httpServer.listen(PORT, () => {
  console.log(`Pure server is running on port ${PORT}`);
  console.log(`Security Notice: Nezha agent and auto-tasks have been removed.`);
});

// 全局未捕获异常处理，防止由于 WebSocket 异常导致的进程退出
process.on('uncaughtException', (err) => {
  console.error('Caught exception:', err.message);
});
