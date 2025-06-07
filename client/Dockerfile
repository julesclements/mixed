# Stage 1: Build the static assets
FROM node:20-slim AS builder

WORKDIR /app/client

# Copy package.json and package-lock.json (if available)
COPY package*.json ./

# Install dependencies
RUN npm install

# Copy the rest of the client application source code
COPY . .

# Build the application
# The output will be in the /app/client/docs directory (as per parcel build script)
RUN npm run build

# Stage 2: Serve the static assets from the 'docs' directory
FROM node:20-alpine AS runner

WORKDIR /app

# Install 'serve' to serve static files
RUN npm install -g serve

# Copy the built assets from the builder stage
COPY --from=builder /app/client/docs ./docs

# Expose the port 'serve' will listen on (default for serve is 3000, but is overridden in CMD)
EXPOSE 1234

# Command to serve the 'docs' directory
# -s flag is important for single-page applications (SPA) to redirect all requests to index.html
# -l flag specifies the listener port
CMD ["serve", "-s", "docs", "-l", "1234"]
