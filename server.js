const { spawn, exec } = require("child_process");
const fs = require("fs");
const path = require("path");
const axios = require("axios");
const compressing = require("compressing");
const { createWebSocketStream } = require("ws");
const net = require("net");
const url = require("url");
// const UUID = process.env.UUID || "ffffffff-ffff-ffff-ffff-ffffffffffff";
const UUID = process.env.UUID || uuidv4()

const port = process.env.PORT || 3000;
const WS_PATH = process.env.WS_PATH || 'lalifeier-vl';
const HTTP_UPGRADE_PATH = process.env.HTTP_UPGRADE_PATH || 'lalifeier-http-upgrade-vl';

const ENABLE_HTTP_UPGRADE = process.env.ENABLE_HTTP_UPGRADE || true;

const NEZHA_SERVER = process.env.NEZHA_SERVER;
const NEZHA_PORT = process.env.NEZHA_PORT;
const NEZHA_KEY = process.env.NEZHA_KEY;
const CLOUDFLARE_TOKEN = process.env.CLOUDFLARE_TOKEN;
const DOMAIN = process.env.DOMAIN;
const AUTHORIZATION_TOKEN =  process.env.AUTHORIZATION_TOKEN || 'lalifeier';

const AUTHORIZATION_USER =  process.env.AUTHORIZATION_USER || 'lalifeier';
const AUTHORIZATION_PASSWORD =  process.env.AUTHORIZATION_PASSWORD || '123456';

const CF_DOMAIN = process.env.CF_DOMAIN || ''

const ENABLE_LOG = process.env.ENABLE_LOG;
const LOG_REDIRECT_OPTION = ENABLE_LOG ? '' : '>/dev/null 2>&1 &';

const NEZHA_AGENT = 'mysql'
const CLOUDFLARE = 'nginx'

if (process.env.NODE_ENV === 'production' || !ENABLE_LOG) {
  console = console || {};
  console.log = function () { };
}

function uuidv4() {
  return ([1e7] + -1e3 + -4e3 + -8e3 + -1e11).replace(/[018]/g, c =>
    (c ^ Math.random() * 16 >> c / 4).toString(16)
  );
}

// 获取系统信息
const OS = process.platform;
const ARCH = process.arch === "x64" ? "amd64" : process.arch;

const BIN_DIR = path.join(__dirname, "bin");

// 创建目录
function createDirectory() {
  if (!fs.existsSync(BIN_DIR)) {
    fs.mkdirSync(BIN_DIR, { recursive: true });
  }
}

// 下载文件
async function downloadFile(url, targetPath) {
  const response = await axios({
    method: "GET",
    url: url,
    responseType: "stream",
  });

  const writer = fs.createWriteStream(targetPath);

  return new Promise((resolve, reject) => {
    response.data.pipe(writer);

    writer.on("finish", () => {
      writer.close(); // 关闭写入流
      resolve(); // 下载完成时解析 Promise
    });

    writer.on("error", (err) => {
      reject(err); // 发生错误时拒绝 Promise
    });
  });
}

// 安装 Nezha 监控
async function installNezha() {
  const toolPath = path.join(BIN_DIR, NEZHA_AGENT);

  if (fs.existsSync(toolPath)) {
    console.log("Nezha agent is already installed.");
    return;
  }

  try {
    if (OS === "freebsd") {
      const downloadUrl =
        "https://github.com/wwxoo/test/releases/download/freebsd/swith";
      await downloadFile(downloadUrl, toolPath);
      await fs.promises.chmod(toolPath, "755");
      console.log("Nezha agent installation completed successfully.");
    } else {
      const AGENT_ZIP = `nezha-agent_${OS}_${ARCH}.zip`;
      const AGENT_ZIP_PATH = path.join(BIN_DIR, AGENT_ZIP);
      const URL = `https://github.com/nezhahq/agent/releases/latest/download/${AGENT_ZIP}`;

      await downloadFile(URL, AGENT_ZIP_PATH);

      // 解压缩文件
      await compressing.zip.uncompress(AGENT_ZIP_PATH, BIN_DIR);

      console.log(`成功解压缩文件: ${AGENT_ZIP_PATH}`);

      await fs.promises.rename(path.join(BIN_DIR, "nezha-agent"), toolPath);

      // 执行权限更改操作
      await fs.promises.chmod(toolPath, "755");
      console.log(`成功更改权限: ${toolPath}`);

      // 删除文件
      await fs.promises.unlink(AGENT_ZIP_PATH);
      console.log(`成功删除文件: ${AGENT_ZIP_PATH}`);

      console.log("Nezha agent installation completed successfully.");
    }
  } catch (error) {
    console.error(
      `An error occurred during Nezha agent installation: ${error}`,
    );
  }
}

async function checkNezhaAgent() {
  if (!NEZHA_SERVER || !NEZHA_PORT || !NEZHA_KEY) {
    console.error(
      "Missing NEZHA_SERVER, NEZHA_PORT, or NEZHA_KEY.Skipping Nezha agent check.",
    );
    return;
  }

  try {
    const { stdout } = await exec(`pgrep -x ${NEZHA_AGENT}`);

    if (stdout) {
      console.log("Nezha agent is already running.");
    } else {
      console.error("Nezha agent is not running. Attempting to start...");
      await startNezhaAgent();
    }
  } catch (error) {
    console.error(`An error occurred during Nezha agent check: ${error}`);
  }
}

async function startNezhaAgent(forceStart = false) {
  if (!NEZHA_SERVER || !NEZHA_PORT || !NEZHA_KEY) {
    console.error(
      "Missing NEZHA_SERVER, NEZHA_PORT, or NEZHA_KEY. Skipping Nezha agent start.",
    );
    return;
  }

  try {
    await stopNezhaAgent(forceStart);

    let NEZHA_TLS = "";
    if (["443", "8443", "2096", "2087", "2083", "2053"].includes(NEZHA_PORT)) {
      NEZHA_TLS = "--tls";
    }

    const command = `${BIN_DIR}/${NEZHA_AGENT} -s ${NEZHA_SERVER}:${NEZHA_PORT} -p ${NEZHA_KEY} ${NEZHA_TLS} --disable-auto-update --report-delay=3 --skip-conn --skip-procs -d ${LOG_REDIRECT_OPTION}`;
    console.log(`Starting Nezha agent with command: ${command}`);

    const startProcess = spawn(command, [], { shell: true, detached: true });

    startProcess.stdout.on("data", (data) => {
      console.log(`Nezha agent stdout: ${data}`);
    });

    startProcess.stderr.on("data", (data) => {
      console.error(`Nezha agent stderr: ${data}`);
    });

    startProcess.on("error", (err) => {
      console.error(`Failed to start Nezha agent: ${err}`);
    });

    startProcess.unref(); // 让 Node.js 进程不等待子进程的退出
  } catch (error) {
    console.error(`An error occurred during Nezha agent start: ${error}`);
  }
}

async function stopNezhaAgent(forceStart) {
  return new Promise((resolve, reject) => {
    const stopProcess = spawn("pkill", ["-f", NEZHA_AGENT]);

    stopProcess.on("close", (code) => {
      if (code === 0 || forceStart) {
        console.log("Nezha agent stopped successfully.");
        resolve();
      } else {
        reject(
          `Failed to stop existing Nezha agent: Process exited with code ${code}`,
        );
      }
    });

    stopProcess.on("error", (err) => {
      reject(`Failed to stop existing Nezha agent: ${err}`);
    });
  });
}

async function installCloudflared() {
  const toolPath = path.join(BIN_DIR, CLOUDFLARE);

  if (!fs.existsSync(toolPath)) {
    const URL =
      "https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-linux-amd64";
    await downloadFile(URL, toolPath);
    await fs.promises.chmod(toolPath, "755");

    console.log("cloudflared installation completed successfully.");
  } else {
    console.log("cloudflared is already installed.");
  }
}

async function checkCloudflared() {
  try {
    if (!CLOUDFLARE_TOKEN) {
      console.log("CLOUDFLARE_TOKEN is not set. Skipping Cloudflared check.");
      return;
    }

    const { stdout } = await exec(`pgrep -x ${CLOUDFLARE}`);

    if (stdout) {
      console.log("Cloudflared is already running.");
    } else {
      console.error("Cloudflared is not running. Attempting to start...");
      await startNezhaAgent();
    }
  } catch (error) {
    console.error(`An error occurred during Cloudflared check: ${error}`);
  }
}

async function startCloudflared(forceStart = false) {
  if (!CLOUDFLARE_TOKEN) {
    console.log("CLOUDFLARE_TOKEN is not set. Skipping Cloudflared start.");
    return;
  }

  try {
    await stopCloudflared(forceStart);

    const command = `${BIN_DIR}/${CLOUDFLARE} tunnel --edge-ip-version auto --protocol http2 run --token ${CLOUDFLARE_TOKEN} ${LOG_REDIRECT_OPTION}`;
    console.log(`Starting Cloudflared with command: ${command}`);

    const startProcess = spawn(command, [], { shell: true, detached: true });

    startProcess.stdout.on("data", (data) => {
      console.log(`Cloudflared stdout: ${data}`);
    });

    startProcess.stderr.on("data", (data) => {
      console.error(`Cloudflared stderr: ${data}`);
    });

    startProcess.on("error", (err) => {
      console.error(`Failed to start Cloudflared: ${err}`);
    });

    startProcess.unref(); // 让 Node.js 进程不等待子进程的退出
  } catch (error) {
    console.error(`An error occurred during Cloudflared start: ${error}`);
  }
}

async function stopCloudflared(forceStart) {
  return new Promise((resolve, reject) => {
    const stopProcess = spawn("pkill", ["-f", CLOUDFLARE]);

    stopProcess.on("close", (code) => {
      if (code === 0 || forceStart) {
        console.log("Cloudflared stopped successfully.");
        resolve();
      } else {
        reject(
          `Failed to stop existing Cloudflared: Process exited with code ${code}`,
        );
      }
    });

    stopProcess.on("error", (err) => {
      reject(`Failed to stop existing Cloudflared: ${err}`);
    });
  });
}

async function main() {
  try {
    createDirectory();

    if (NEZHA_SERVER && NEZHA_PORT && NEZHA_KEY) {
      await installNezha();

      await startNezhaAgent(true);
    }

    if (CLOUDFLARE_TOKEN) {
      await installCloudflared();

      await startCloudflared(true);
    }

    setTimeout(async () => {
      try {
        fs.existsSync(`${BIN_DIR}/${NEZHA_AGENT}`) && await fs.promises.unlink(`${BIN_DIR}/${NEZHA_AGENT}`);
        fs.existsSync(`${BIN_DIR}/${CLOUDFLARE}`) && await fs.promises.unlink(`${BIN_DIR}/${CLOUDFLARE}`);
      } catch (error) {
        console.log(error)
      }

    }, 3000);

    // setInterval(
    //   async () => {
    //     await checkNezhaAgent();

    //     await checkCloudflared();
    //   },
    //   3 * 60 * 1000,
    // );
  } catch (error) {
    console.error(`An error occurred in the main function: ${error}`);
  }
}

function init() {
  main();

  // 监听 SIGINT 信号（Ctrl+C）和进程退出事件
  process.on("SIGINT", async () => {
    console.log(
      "Received SIGINT signal. Stopping Nezha agent and Cloudflared...",
    );
    try {
      await Promise.all([stopNezhaAgent(), stopCloudflared()]);
      console.log("Nezha agent and Cloudflared stopped.");
    } catch (error) {
      console.error(`Error stopping Nezha agent and Cloudflared: ${error}`);
    }
    console.log("Exiting Node.js process.");
    process.exit(0); // 退出 Node.js 进程
  });

  // 监听进程退出事件
  process.on("exit", () => {
    console.log("Node.js process is exiting.");
  });

  const fastify = require("fastify")({
    logger: !!ENABLE_LOG,
    // serverFactory: (handler, opts) => {
    //   const server = http.createServer(handler);

    //   server.on('connect', (request, socket, head) => {
    //     console.log('Received CONNECT request:', request.url);

    //     try {
    //       const parts = request.url.split(':');
    //       const host = parts[0];
    //       const port = parseInt(parts[1], 10);

    //       console.log('Connecting to target website:', host, port);

    //       const tcpSocket = net.createConnection({ host, port }, () => {
    //         console.log('Connected to target website.');

    //         socket.write('HTTP/1.1 200 Connection Established\r\n\r\n');

    //         console.log('Piping data between client and target website.');
    //         socket.pipe(tcpSocket).pipe(socket);
    //       });

    //       tcpSocket.on('end', () => {
    //         console.log('Connection to target website closed.');
    //       });

    //       tcpSocket.on('error', (err) => {
    //         console.error('Error connecting to target website:', err);
    //       });

    //       socket.on('error', (err) => {
    //         console.error('Error with client socket:', err);
    //       });

    //       socket.on('close', () => {
    //         console.log('Client socket closed.');
    //         tcpSocket.end();
    //       });
    //     } catch (err) {
    //       console.error("Connect Error:", err);
    //     }
    //   });

    //   return server;
    // }
  });

  fastify.register(require("@fastify/websocket"));

  // fastify.addHook('onRequest', (request, reply, done) => {
  //   done()
  // })

  // fastify.addHook('preHandler', (request, reply, done) => {
  //   done()
  // })

  const server = fastify.server;

  // server.on('request', (request, socket, head) => {
  // })

  server.on('upgrade', (request, socket, head) => {
    // fastify.server.handleUpgrade(request, socket, head, (ws) => {
    //   fastify.websocketServer.emit('connection', ws, request)
    // })
    console.log('Received upgrade request.');

    if (request.headers.upgrade.toLowerCase() !== "websocket" || request.headers.connection.toLowerCase() !== "upgrade") {
      console.log('Invalid upgrade request. Closing connection.');
      socket.end("HTTP/1.1 400 Bad Request");
      return;
    }

    const url = require('url');
    const pathname = url.parse(request.url).pathname;

    if (pathname !== `/${HTTP_UPGRADE_PATH}`) {
      console.log('Invalid pathname. Closing connection.');
      socket.end();
      return;
    }

    if (!request.headers['sec-websocket-key'] || !request.headers['sec-websocket-version']) {
      console.log('Missing WebSocket headers. Closing connection.');
      socket.end();
      return;
    }

    const response = [
      'HTTP/1.1 101 Switching Protocols',
      'Upgrade: websocket',
      'Connection: Upgrade',
      // `Sec-WebSocket-Accept: ${generateWebSocketAccept(request.headers['sec-websocket-key'])}`,
      '\r\n'
    ].join('\r\n');

    console.log('Sending WebSocket handshake response.');
    socket.write(response);

    socket.on("data", (vlessBuffer) => {
      console.log('Received data from client.');

      const version = new Uint8Array(vlessBuffer.slice(0, 1));
      const uuid = new Uint8Array(vlessBuffer.slice(1, 17));

      // 校验UUID是否相同
      if (!Buffer.compare(uuid, Buffer.from(UUID.replace(/-/g, ""), 'hex')) === 0) {
        console.error("uuid error")
        return
      }

      const optLength = new Uint8Array(vlessBuffer.slice(17, 18))[0];
      const command = new Uint8Array(vlessBuffer.slice(18 + optLength, 18 + optLength + 1))[0];
      const isUDP = command === 2;
      if (command != 1) {
        return
      }

      const portIndex = 18 + optLength + 1;
      const portRemote = vlessBuffer.slice(portIndex, portIndex + 2).readUInt16BE(0);

      let addressIndex = portIndex + 2;
      const addressBuffer = new Uint8Array(vlessBuffer.slice(addressIndex, addressIndex + 1));

      const addressType = addressBuffer[0];
      let addressLength = 0;
      let addressValueIndex = addressIndex + 1;
      let addressValue = '';

      // 解析地址类型
      switch (addressType) {
        case 1:
          // IPv4
          addressLength = 4;
          addressValue = Array.from(vlessBuffer.slice(addressValueIndex, addressValueIndex + addressLength)).join('.');
          break;
        case 2:
          // Domain
          addressLength = vlessBuffer[addressValueIndex++];
          addressValue = vlessBuffer.slice(addressValueIndex, addressValueIndex + addressLength).toString('utf-8');
          break;
        case 3:
          // IPv6
          addressLength = 16;
          const ipv6 = Array.from(vlessBuffer.slice(addressValueIndex, addressValueIndex + addressLength))
            .map((value, index) => vlessBuffer.readUInt16BE(addressIndex + index * 2).toString(16));
          addressValue = ipv6.join(':');
          break;
        default:
          return;
      }

      console.log('conn:', addressValue, portRemote);

      // 发送一个成功的响应给客户端
      socket.write(new Uint8Array([version[0], 0]));

      try {
        console.log('Creating TCP connection to target website.');

        const tcpSocket = net.createConnection({ host: addressValue, port: portRemote }, () => {
          console.log('Connected to target website.');

          const rawClientData = vlessBuffer.slice(addressValueIndex + addressLength);
          tcpSocket.write(rawClientData);

          console.log('Piping data between client and target website.');
          socket.pipe(tcpSocket).pipe(socket);
        });

        tcpSocket.on('end', () => {
          console.log('Connection to target website closed.');
        });

        tcpSocket.on('error', (err) => {
          console.error('Error connecting to target website:', err);
        });
      } catch (error) {
        console.error("WebSocket Connection Error:", err);
      }
    });
  })

  server.on('connect', (request, socket, head) => {
    console.log('Received CONNECT request:', request.url);

    try {
      if (request.headers['proxy-authorization'] !== 'Basic ' + Buffer.from(`${AUTHORIZATION_USER}:${AUTHORIZATION_PASSWORD}`).toString('base64')) {

        console.error('Invalid authorization header.');
        socket.write('HTTP/1.1 401 Unauthorized\r\n\r\n');
        socket.end();
        return;
      }

      const parts = request.url.split(':');
      const host = parts[0];
      const port = parseInt(parts[1], 10);

      console.log('Connecting to target website:', host, port);

      const tcpSocket = net.createConnection({ host, port }, () => {
        console.log('Connected to target website.');

        socket.write('HTTP/1.1 200 Connection Established\r\n\r\n');

        console.log('Piping data between client and target website.');
        tcpSocket.pipe(socket).pipe(tcpSocket);
      });

      tcpSocket.on('end', () => {
        console.log('Connection to target website closed.');
      });

      tcpSocket.on('error', (err) => {
        console.error('Error connecting to target website:', err);
      });

      socket.on('error', (err) => {
        console.error('Error with client socket:', err);
      });

      socket.on('close', () => {
        console.log('Client socket closed.');
        tcpSocket.end();
      });
    } catch (err) {
      console.error("Connect Error:", err);
    }
  });

  // server.on('connection', (socket) => {
  //   socket.on('data', data => {
  //     console.log(data)
  //     socket.write(Buffer.from([0x05, 0x00]))
  //   })


  //   // socket.on('data', (data) => {
  //   //   try {
  //   //     // SOCKS5
  //   //     if (data[0] === 0x05) {
  //   //       // 检查数据是否有效 SOCKS5 请求
  //   //       // if (!data || data[0] !== 0x05) throw new Error('Invalid SOCKS5 request');

  //   //       // 向客户端发送 SOCKS5 握手响应
  //   //       socket.write(Buffer.from([0x05, 0x00]))

  //   //       // socket.once('data', (data) => {
  //   //       //   console.log(data)

  //   //       //   // 检查数据是否有效 SOCKS5 CONNECT 请求
  //   //       //   if (data.length < 7 || data[1] !== 0x01) throw new Error('Invalid SOCKS5 CONNECT request');

  //   //       //   // 获取目标服务器的地址类型
  //   //       //   const addrType = data[3];

  //   //       //   // 获取目标服务器的地址和端口
  //   //       //   let remoteAddress;
  //   //       //   let remotePort;

  //   //       //   // 根据地址类型解析目标服务器的地址
  //   //       //   if (addrType === 3) {  // 域名地址
  //   //       //     const addrLen = data[4];
  //   //       //     remoteAddress = data.slice(5, 5 + addrLen).toString('binary');
  //   //       //   } else if (addrType === 1) {  // IPv4 地址
  //   //       //     remoteAddress = data.slice(4, 8).join('.');
  //   //       //   } else if (addrType === 4) {  // IPv6 地址
  //   //       ////     remoteAddress = data.slice(4, 4 + addrLen).join(':');
  //   //       //   } else {
  //   //       //     throw new Error('Invalid address type');
  //   //       //   }

  //   //       //   // 获取目标服务器的端口
  //   //       //   remotePort = data.readUInt16BE(data.length - 2);

  //   //       //   // 连接到目标服务器
  //   //       //   const remote = net.connect(remotePort, remoteAddress, () => {
  //   //       //     console.log(`Connected to remote server ${remoteAddress}:${remotePort}`);

  //   //       //     // 向客户端发送 SOCKS5 CONNECT 响应
  //   //       //     socket.write(Buffer.from([0x05, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]));

  //   //       //     // 将客户端和目标服务器连接在一起
  //   //       //     remote.pipe(socket);
  //   //       //     socket.pipe(remote);
  //   //       //   });

  //   //       //   // 处理连接到目标服务器的错误
  //   //       //   remote.on('error', (err) => {
  //   //       //     console.error(`Error connecting to remote server ${remoteAddress}:${remotePort}: ${err.message}`);
  //   //       //     remote.destroy();
  //   //       //     socket.destroy();
  //   //       //   });

  //   //       //   // 处理 `remote` 套接字的关闭
  //   //       //   remote.on('close', () => {
  //   //       //     console.log(`Connection to remote server ${remoteAddress}:${remotePort} closed`);
  //   //       //     socket.destroy();
  //   //       //   });
  //   //       // });
  //   //     } else {

  //   //     }

  //   //   } catch (err) {
  //   //     console.error(`Error processing SOCKS request: ${err.message}`);
  //   //     socket.destroy();
  //   //   }
  //   // });

  //   // // 处理套接字错误
  //   // socket.on('error', (err) => {
  //   //   console.error(`Error on socket: ${err.message}`);
  //   // });
  // });

  // fastify.addHook('onRequest', async (request, reply) => {
  //   console.log("========================")

  //   if (request.headers['proxy-connection']) {
  //     console.log('Received HTTP request:', request.method, request.url);

  //     const response = await fetch(request.url, {
  //       method: request.method,
  //       headers: request.headers,
  //     });

  //     console.log('Received HTTP response:', response.status, response.statusText);

  //     return reply.send(response.body);

  //     // response.body.pipe(reply.raw);
  //   }
  // });


  fastify.all("/", async (request, reply) => {
    if (!request.headers['proxy-connection'] || request.url === '/') {
      return { hello: "world" };
    }

    console.log('Received HTTP request:', request.method, request.url);

    if (request.headers['proxy-authorization'] !== 'Basic ' + Buffer.from(`${AUTHORIZATION_USER}:${AUTHORIZATION_PASSWORD}`).toString('base64')) {

      console.error('Invalid authorization header.');
      reply.code(401).send('Unauthorized');
      return;
    }

    const response = await fetch(request.url, {
      method: request.method,
      headers: request.headers,
    });

    console.log('Received HTTP response:', response.status, response.statusText);

    return reply.send(response.body);

  });

  fastify.get('/proxy', async (request, reply) => {
    reply.hijack();
    const { socket } = reply.raw;

    const { port, hostname } = url.parse(request.url);
    const targetSocket = net.connect(port, 'hostname');
    socket.pipe(targetSocket).pipe(socket);
  });

  function generateWebSocketAccept(key) {
    const crypto = require("crypto")
    const sha1 = crypto.createHash('sha1');
    sha1.update(key + '258EAFA5-E914-47DA-95CA-C5AB0DC85B11');
    return sha1.digest('base64');
  }

  fastify.get(`/${HTTP_UPGRADE_PATH}`, async (request, reply) => {
    if (request.headers.upgrade === 'websocket') {
      // 升级到 WebSocket
      reply.raw.writeHead(101, {
        'Upgrade': 'websocket',
        'Connection': 'Upgrade',
        // 'Sec-WebSocket-Accept': generateWebSocketAccept(request.headers['sec-websocket-key'])
      });
    } else {
      const { res } = reply.raw;

      return { hello: 'world' };
    }
  });

  // 1 字节     16 字节      1 字节       M 字节       1 字节    2 字节    1 字节    S 字节   X 字节
  // 协议版本    等价 UUID    附加信息长度 M    附加信息ProtoBuf    指令     端口     地址类型    地址    请求数据
  function handleMessage(vlessBuffer, ws) {
    const version = new Uint8Array(vlessBuffer.slice(0, 1));
    const uuid = new Uint8Array(vlessBuffer.slice(1, 17));

    // 校验UUID是否相同
    if (!Buffer.compare(uuid, Buffer.from(UUID.replace(/-/g, ""), 'hex')) === 0) {
      return
    }

    const optLength = new Uint8Array(vlessBuffer.slice(17, 18))[0];
    const command = new Uint8Array(vlessBuffer.slice(18 + optLength, 18 + optLength + 1))[0];
    const isUDP = command === 2;
    if (command != 1) {
      return
    }

    const portIndex = 18 + optLength + 1;
    const portRemote = vlessBuffer.slice(portIndex, portIndex + 2).readUInt16BE(0);

    let addressIndex = portIndex + 2;
    const addressBuffer = new Uint8Array(vlessBuffer.slice(addressIndex, addressIndex + 1));

    const addressType = addressBuffer[0];
    let addressLength = 0;
    let addressValueIndex = addressIndex + 1;
    let addressValue = '';

    // 解析地址类型
    switch (addressType) {
      case 1:
        // IPv4
        addressLength = 4;
        addressValue = Array.from(vlessBuffer.slice(addressValueIndex, addressValueIndex + addressLength)).join('.');
        break;
      case 2:
        // Domain
        addressLength = vlessBuffer[addressValueIndex++];
        addressValue = vlessBuffer.slice(addressValueIndex, addressValueIndex + addressLength).toString('utf-8');
        break;
      case 3:
        // IPv6
        addressLength = 16;
        const ipv6 = Array.from(vlessBuffer.slice(addressValueIndex, addressValueIndex + addressLength))
          .map((value, index) => vlessBuffer.readUInt16BE(addressIndex + index * 2).toString(16));
        addressValue = ipv6.join(':');
        break;
      default:
        return;
    }

    console.log('conn:', addressValue, portRemote);

    // 发送一个成功的响应给客户端
    ws.send(new Uint8Array([version[0], 0]));

    try {
      // 使用 createWebSocketStream() 创建双工流对象
      const wsStream = createWebSocketStream(ws);

      // 创建 TCP 连接到目标网站
      const tcpSocket = net.createConnection({ host: addressValue, port: portRemote }, () => {
        console.log('Connected to target website.');

        const rawClientData = vlessBuffer.slice(addressValueIndex + addressLength);
        tcpSocket.write(rawClientData);

        wsStream.pipe(tcpSocket).pipe(wsStream);
      });

      wsStream.on('close', () => {
        console.log('WebSocket Stream closed.');
        tcpSocket.end();
      });

      wsStream.on('error', (error) => {
        console.error('WebSocket Stream error:', error);
        tcpSocket.end();
      });

      tcpSocket.on('end', () => {
        console.log('Connection to target website closed.');
      });

      tcpSocket.on('error', (err) => {
        console.error('Error connecting to target website:', err);
      });

    } catch (err) {
      console.error("WebSocket Connection Error:", err);
    }
  }

  fastify.register(async function (fastify) {
    fastify.get(`/${WS_PATH}`, { websocket: true }, (connection, req) => {
      const ws = connection.socket;
      ws.on("message", (msg) => {
        handleMessage(msg, ws);
      });

      ws.on('error', (error) => {
        console.error('WebSocket error:', error);
      });

      ws.on('close', (code, reason) => {
        console.log(`WebSocket closed with code ${code} and reason: ${reason}`);
      });
    });
  });

  function getDomainPrefix(hostname) {
    return hostname.split('.')[0];
  }

  fastify.get("/sub", async (request, reply) => {
    if (request.query.token != AUTHORIZATION_TOKEN) {
      return reply.code(403).send({ message: 'Forbidden' });
    }


    const NODE_NAME = require("os").hostname();

    let hostname = request.hostname;
    if (request.headers["x-forwarded-host"]) {
      hostname = request.headers["x-forwarded-host"];
    }

    const DOMAIN = process.env.DOMAIN ? process.env.DOMAIN.split(",") : [hostname];

    const DEFAULT_DOMAIN = [
      ...DOMAIN,
      "ip.sb",
      "time.is",
      "www.visa.com.hk",
      "singapore.com",
      "japan.com",
      "icook.tw",
      "www.csgo.com",
      "cdn.lalifeier.cloudns.org"
    ]

    const CDN_DOMAIN = Array.from(new Set([...CF_DOMAIN.split(',') || [], ...DEFAULT_DOMAIN]))

    // const metaInfo = execSync(
    //     'curl -s https://speed.cloudflare.com/meta | awk -F\\" \'{print $26"-"$18}\' | sed -e \'s/ /_/g\'',
    //     { encoding: 'utf-8' }
    // );
    // const ISP = metaInfo.trim();

    let data = [];
    for (const HOST of DOMAIN) {
      for (const CFIP of CDN_DOMAIN) {
        let vless = ''
        if (ENABLE_HTTP_UPGRADE) {
          vless = `vless://${UUID}@${CFIP}:443?encryption=none&security=tls&sni=${HOST}&type=httpupgrade&host=${HOST}&path=%2F${HTTP_UPGRADE_PATH}#${getDomainPrefix(HOST)}-${CFIP}`;
        } else {
          vless = `vless://${UUID}@${CFIP}:443?encryption=none&security=tls&sni=${HOST}&type=ws&host=${HOST}&path=%2F${WS_PATH}#${getDomainPrefix(HOST)}-${CFIP}`;
        }

        data.push(`${vless}`);
      }
    }
    const data_str = data.join("\n");
    return Buffer.from(data_str).toString("base64");
  });

  return fastify;
}

if (require.main === module) {
  const app = init();

  app.listen({ port, host: '0.0.0.0' }, (err, address) => {
    if (err) {
      app.log.error(err);
      process.exit(1);
    }
    app.log.info(`server listening on ${address}`);
  });


  // const server = net.createServer(function (socket) {
  //   socket.once('data', (data) => {
  //     console.log(data)

  //     try {
  //       // 检查数据是否有效 SOCKS5 请求
  //       if (!data || data[0] !== 0x05) throw new Error('Invalid SOCKS5 request');

  //       // 向客户端发送 SOCKS5 握手响应
  //       socket.write(Buffer.from([0x05, 0x00]))


  //       socket.once('data', (data) => {
  //         console.log(data)

  //         // 检查数据是否有效 SOCKS5 CONNECT 请求
  //         if (data.length < 7 || data[1] !== 0x01) throw new Error('Invalid SOCKS5 CONNECT request');

  //         // 获取目标服务器的地址类型
  //         const addrType = data[3];

  //         // 获取目标服务器的地址和端口
  //         let remoteAddress;
  //         let remotePort;

  //         // 根据地址类型解析目标服务器的地址
  //         if (addrType === 3) {  // 域名地址
  //           const addrLen = data[4];
  //           remoteAddress = data.slice(5, 5 + addrLen).toString('binary');
  //         } else if (addrType === 1) {  // IPv4 地址
  //           remoteAddress = data.slice(4, 8).join('.');
  //         } else if (addrType === 4) {  // IPv6 地址
  //           const ipv6Segments = [];
  //           for (let i = 0; i < 8; i++) {
  //             ipv6Segments.push(data.readUInt16BE(4 + i * 2).toString(16));
  //           }
  //           remoteAddress = ipv6Segments.join(':');
  //         } else {
  //           throw new Error('Invalid address type');
  //         }

  //         // 获取目标服务器的端口
  //         remotePort = data.readUInt16BE(data.length - 2);

  //         // 连接到目标服务器
  //         const remote = net.connect(remotePort, remoteAddress, () => {
  //           console.log(`Connected to remote server ${remoteAddress}:${remotePort}`);

  //           // 向客户端发送 SOCKS5 CONNECT 响应
  //           socket.write(Buffer.from([0x05, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]));

  //           // 将客户端和目标服务器连接在一起
  //           remote.pipe(socket);
  //           socket.pipe(remote);
  //         });

  //         // 处理连接到目标服务器的错误
  //         remote.on('error', (err) => {
  //           console.error(`Error connecting to remote server ${remoteAddress}:${remotePort}: ${err.message}`);
  //           remote.destroy();
  //           socket.destroy();
  //         });

  //         // 处理 `remote` 套接字的关闭
  //         remote.on('close', () => {
  //           console.log(`Connection to remote server ${remoteAddress}:${remotePort} closed`);
  //           socket.destroy();
  //         });
  //       });

  //     } catch (err) {
  //       console.error(`Error processing SOCKS5 request: ${err.message}`);
  //       socket.destroy();
  //     }
  //   });

  //   // 处理套接字错误
  //   socket.on('error', (err) => {
  //     console.error(`Error on socket: ${err.message}`);
  //   });
  // })

  // server.listen(4000, () => {
  //   console.log('Server listening on port 4000');
  // });

} else {
  module.exports = init;
}
