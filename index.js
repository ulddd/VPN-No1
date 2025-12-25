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
const UUID = process.env.UUID || '7f2b8a5c-d9e1-4b36-a52f-c10a8e947d1b'; 
const DOMAIN = process.env.DOMAIN || '';           
const WSPATH = process.env.WSPATH || UUID.slice(0, 8); 
const SUB_PATH = process.env.SUB_PATH || 'sub';    
const NAME = process.env.NAME || 'WildGuard-Node'; 
const PORT = process.env.PORT || 7860;             

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

const httpServer = http.createServer((req, res) => {
  if (req.url === '/') {
    const filePath = path.join(__dirname, 'index.html');
    fs.readFile(filePath, 'utf8', (err, content) => {
      res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
      res.end(err ? 'Service Running' : content);
    });
  } else if (req.url === `/${SUB_PATH}`) {
    const namePart = NAME ? `${NAME}-${ISP}` : ISP;
    const subscription = Buffer.from(
      `vless://${UUID}@${DOMAIN}:443?encryption=none&security=tls&sni=${DOMAIN}&fp=chrome&type=ws&host=${DOMAIN}&path=%2F${WSPATH}#${namePart}\n` +
      `trojan://${UUID}@${DOMAIN}:443?security=tls&sni=${DOMAIN}&fp=chrome&type=ws&host=${DOMAIN}&path=%2F${WSPATH}#${namePart}`
    ).toString('base64');
    res.writeHead(200, { 'Content-Type': 'text/plain; charset=utf-8' });
    res.end(subscription + '\n');
  } else {
    res.writeHead(404);
    res.end();
  }
});

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

    duplex.on('error', () => { 
        duplex.destroy();
        if (ws.readyState === WebSocket.OPEN) ws.close();
    });

    if (isVless) {
      const id = msg.slice(1, 17);
      if (!id.every((v, i) => v == parseInt(cleanUuid.substr(i * 2, 2), 16))) return ws.close();
      
      let i = msg.slice(17, 18).readUInt8() + 19;
      const port = msg.slice(i, i += 2).readUInt16BE(0);
      const ATYP = msg.slice(i, i += 1).readUInt8();
      
      let host = "";
      if (ATYP == 1) {
        host = msg.slice(i, i += 4).join('.');
      } else if (ATYP == 2) {
        const len = msg.slice(i, i += 1).readUInt8();
        host = new TextDecoder().decode(msg.slice(i, i += len));
      } else if (ATYP == 3) {
        host = "localhost";
      }

      ws.send(new Uint8Array([0, 0]));

      resolveHost(host).then(ip => {
        const socket = net.connect({ host: ip, port }, function() {
          this.write(msg.slice(i));
          duplex.pipe(this).on('error', () => {
              duplex.destroy();
              this.destroy();
          }).pipe(duplex);
        });
        socket.on('error', () => { 
            duplex.destroy();
            if (ws.readyState === WebSocket.OPEN) ws.close();
        });
      }).catch(() => {
          if (ws.readyState === WebSocket.OPEN) ws.close();
      });

    } else {
      try {
        const receivedHash = msg.slice(0, 56).toString();
        const expectedHash = crypto.createHash('sha224').update(UUID).digest('hex');
        if (receivedHash !== expectedHash) return ws.close();
        
        const socket = net.connect({ host: 'localhost', port: 80 }, () => {
           duplex.pipe(socket).on('error', () => {
               duplex.destroy();
               socket.destroy();
           }).pipe(duplex);
        });
        socket.on('error', () => { duplex.destroy(); });
      } catch (e) { ws.close(); }
    }
  });

  ws.on('error', () => {}); 
});

httpServer.listen(PORT, () => {
  console.log(`Pure server is running on port ${PORT}`);
});

process.on('uncaughtException', (err) => {
  console.error('Caught exception:', err.message);
});
