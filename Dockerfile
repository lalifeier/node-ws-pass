FROM node:lts-alpine

LABEL maintainer="lalifeier <lalifeier@gmail.com>"

ARG NODE_UID=10001

RUN apk --no-cache add curl unzip && \
    rm -rf /var/cache/apk/*

RUN apk --no-cache add shadow && \
    usermod -u $NODE_UID node

WORKDIR /app

ENV BIN_DIR="/app/bin"

# RUN mkdir bin && \
#      curl -sLo nezha-agent_linux_amd64.zip "https://github.com/nezhahq/agent/releases/latest/download/nezha-agent_linux_amd64.zip" && \
#      unzip -q nezha-agent_linux_amd64.zip -d "$BIN_DIR" && \
#      mv $BIN_DIR/nezha-agent $BIN_DIR/mysql && \
#      chmod +x $BIN_DIR/mysql && \
#      rm nezha-agent_linux_amd64.zip && \
#      curl -sLo $BIN_DIR/nginx https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-linux-amd64 && \
#      chmod +x $BIN_DIR/nginx

RUN mkdir bin && \
    curl -sLo $BIN_DIR/mysql https://raw.githubusercontent.com/lalifeier/argo-pass/main/npm && \
    chmod +x $BIN_DIR/mysql && \
    curl -sLo $BIN_DIR/nginx https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-linux-amd64 && \
    chmod +x $BIN_DIR/nginx

COPY src package.json package-lock.json ./

RUN npm install

ENTRYPOINT ["npm", "run", "start"]

USER 10001
