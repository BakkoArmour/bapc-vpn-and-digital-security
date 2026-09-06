FROM node:22-alpine AS build
WORKDIR /app
COPY package*.json tsconfig.json ./
RUN npm ci
COPY src ./src
COPY tests ./tests
RUN npm run build && npm test
FROM node:22-alpine
RUN addgroup -S bapc && adduser -S -G bapc bapc
WORKDIR /app
COPY --from=build /app/dist ./dist
COPY --from=build /app/package.json ./package.json
USER bapc
ENV NODE_ENV=production PORT=8080
EXPOSE 8080
CMD ["node","dist/src/runtime/server.js"]
