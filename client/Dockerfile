# Stage 1: Build the static assets
FROM node:26-slim AS builder

WORKDIR /app/client

# Copy the manifest and patched lockfile
COPY package.json package-lock.json ./

# Install dependencies
RUN npm ci

# Copy the rest of the client application source code
COPY . .

# Build the application
# The output will be in the /app/client/docs directory (as per parcel build script)
RUN npm run build

# Stage 2: Serve the static assets from the 'docs' directory
FROM node:26-alpine AS runner

WORKDIR /app

# Install 'serve' to serve static files
RUN npm install -g serve@14.2.7

# Copy the built assets from the builder stage
COPY --from=builder /app/client/docs ./docs

# Expose the port 'serve' will listen on (default for serve is 3000, but is overridden in CMD)
EXPOSE 1234

# Command to serve the 'docs' directory
# -s flag is important for single-page applications (SPA) to redirect all requests to index.html
# -l flag specifies the listener port
CMD ["serve", "-s", "docs", "-l", "1234"]
