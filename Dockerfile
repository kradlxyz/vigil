FROM node:22-alpine
WORKDIR /app
COPY package.json ./
RUN npm install --omit=dev=false
COPY tsconfig.json ./
COPY src ./src
COPY public ./public
RUN npm run build
ENV PORT=3010
EXPOSE 3010
CMD ["npm", "start"]
