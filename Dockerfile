FROM node:24-bullseye-slim AS builder

WORKDIR /app

COPY package.json yarn.lock ./

RUN apt-get update && apt-get install -y \
	build-essential \
	git \
	ca-certificates \
	&& rm -rf /var/lib/apt/lists/*

COPY . .
RUN yarn install --frozen-lockfile && yarn build && rm -rf node_modules/ && yarn install --frozen-lockfile --production


FROM gcr.io/distroless/nodejs24-debian12 AS production
WORKDIR /home/node/app
USER nonroot

COPY --from=builder --chown=nonroot:nonroot /app/package.json .
COPY --from=builder --chown=nonroot:nonroot /app/dist ./dist
COPY --from=builder --chown=nonroot:nonroot /app/src/config/oauth2clients.json ./src/config/oauth2clients.json
COPY --from=builder --chown=nonroot:nonroot /app/src/views ./src/views
COPY --from=builder --chown=nonroot:nonroot /app/node_modules ./node_modules
COPY --from=builder --chown=nonroot:nonroot /app/public ./public

ENV NODE_ENV=production

EXPOSE 6060

CMD ["./dist/app.js"]
