FROM node:trixie-slim

WORKDIR /app

COPY --chown=node:node package.json /app/package.json
RUN npm install --omit=dev

COPY --chown=node:node server.js /app/server.js
COPY --chown=node:node public /app/public

USER node

EXPOSE 3000

CMD ["npm", "start"]
