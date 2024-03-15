const { spawn, exec } = require("child_process");
const fs = require("fs");
const path = require("path");
const axios = require("axios");
const compressing = require("compressing");
const { createWebSocketStream } = require("ws");
const net = require("net");

const cron = require('node-cron');


// const UUID = process.env.UUID || "ffffffff-ffff-ffff-ffff-ffffffffffff";
const UUID = process.env.UUID || uuidv4()

const port = process.env.PORT || 3000;
const WS_PATH = process.env.WS_PATH || 'lalifeier-vl';

const NEZHA_SERVER = process.env.NEZHA_SERVER;
const NEZHA_PORT = process.env.NEZHA_PORT;
const NEZHA_KEY = process.env.NEZHA_KEY;
const CLOUDFLARE_TOKEN = process.env.CLOUDFLARE_TOKEN;
const DOMAIN = process.env.DOMAIN;

const CF_DOMAIN = process.env.CF_DOMAIN || ''

const ENABLE_LOG = process.env.ENABLE_LOG;
const LOG_REDIRECT_OPTION = ENABLE_LOG ? '' : '>/dev/null 2>&1 &';

const NEZHA_AGENT = 'mysql'
const CLOUDFLARE = 'nginx'

if (process.env.NODE_ENV === 'production' || !ENABLE_LOG) {
  console = console || {};
  console.log = function () { };
}

const uuidv4 = () => ([1e7]+-1e3+-4e3+-8e3+-1e11).replace(/[018]/g,c =>
  (c^Math.random()*16>>c/4).toString(16)
);

// 获取系统信息
const OS = process.platform;
const ARCH = process.arch === "x64" ? "amd64" : process.arch;

const BIN_DIR = path.join(__dirname, "bin");

// 创建目录
function createDirectory () {
  if (!fs.existsSync(BIN_DIR)) {
    fs.mkdirSync(BIN_DIR, { recursive: true });
  }
}

// 下载文件
async function downloadFile (url, targetPath) {
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
async function installNezha () {
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

async function checkNezhaAgent () {
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

async function startNezhaAgent (forceStart = false) {
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

async function stopNezhaAgent (forceStart) {
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

async function installCloudflared () {
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

async function checkCloudflared () {
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

async function startCloudflared (forceStart = false) {
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

async function stopCloudflared (forceStart) {
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

async function main () {
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

function init () {
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

  const fastify = require("fastify")({ logger: true });

  fastify.register(require("@fastify/websocket"));

  fastify.get("/", async (request, reply) => {
    return { hello: "world" };
  });

  // 1 字节     16 字节      1 字节       M 字节       1 字节    2 字节    1 字节    S 字节   X 字节
  // 协议版本    等价 UUID    附加信息长度 M    附加信息ProtoBuf    指令     端口     地址类型    地址    请求数据
  function handleMessage (vlessBuffer, ws) {
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

  function getDomainPrefix (hostname) {
    return hostname.split('.')[0];
  }

  fastify.get("/sub", async (request, reply) => {
    const NODE_NAME = require("os").hostname();

    let hostname = request.hostname;
    if (request.headers["x-forwarded-host"]) {
      hostname = request.headers["x-forwarded-host"];
    }

    const DOMAIN = process.env.DOMAIN ? process.env.DOMAIN.split(",") : [hostname];

    const DEFAULT_DOMAIN =  [
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
        const vless = `vless://${UUID}@${CFIP}:443?encryption=none&security=tls&sni=${HOST}&type=ws&host=${HOST}&path=%2F${WS_PATH}#${getDomainPrefix(HOST)}-${CFIP}`;
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

  app.listen({ port }, (err, address) => {
    if (err) {
      app.log.error(err);
      process.exit(1);
    }
    app.log.info(`server listening on ${address}`);
  });
} else {
  module.exports = init;
}
