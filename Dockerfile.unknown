# Use an official Node.js image
FROM node:22-alpine

# Create app directory
WORKDIR /app

# Install packages to build sqlite3 from source
RUN apk add --no-cache py3-setuptools make g++

# Copy package files and install dependencies
COPY package.json .

# Copy the rest of the source code
COPY . .

RUN npm install -g npm
RUN npm install
RUN npm rebuild sqlite3 --build-from-source
RUN npm run init

# Expose both HTTP and WebSocket ports
EXPOSE 3000
EXPOSE 4000

# Start the server
CMD ["npm", "start"]