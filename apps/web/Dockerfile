FROM docker.1ms.run/library/node:20-bookworm AS builder

WORKDIR /usr/src/web

COPY package.json package-lock.json ./
RUN npm ci

COPY tsconfig.json ./
COPY next.config.ts ./
COPY next-env.d.ts ./
COPY app ./app
COPY components ./components
COPY lib ./lib
COPY middleware.ts ./middleware.ts

RUN npm run build

FROM docker.1ms.run/library/node:20-bookworm AS runner

WORKDIR /usr/src/web
ENV NODE_ENV=production
ENV PORT=3000
ENV HOSTNAME=0.0.0.0

# Standalone output already contains the minimal runtime dependencies.
COPY --from=builder /usr/src/web/.next/standalone ./
COPY --from=builder /usr/src/web/.next/static ./.next/static

EXPOSE 3000

CMD ["node", "server.js"]
