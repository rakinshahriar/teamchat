FROM node:trixie-slim

WORKDIR /app

COPY package.json /app/package.json
RUN npm install --omit=dev

COPY server.js /app/server.js
COPY public /app/public

EXPOSE 3000

CMD ["npm", "start"]
