# Stage 1: Build the static assets for the SPA
FROM node:26-slim AS builder

WORKDIR /app/spa

# Copy the manifest and patched lockfile
COPY package.json package-lock.json ./

# Install dependencies
RUN npm ci

# Copy the rest of the SPA application source code
COPY . .

# Vite inlines VITE_* variables at build time; .env files are excluded from the context.
ARG VITE_STAFF_CLIENT_ID
ARG VITE_PING_BASE_URL
ENV VITE_STAFF_CLIENT_ID=$VITE_STAFF_CLIENT_ID \
    VITE_PING_BASE_URL=$VITE_PING_BASE_URL

# Build the application
# The output will be in the /app/spa/dist directory
RUN npm run build

# Stage 2: Serve the static assets from the 'dist' directory
FROM node:26-alpine AS runner

WORKDIR /app

# Install 'serve' to serve static files
RUN npm install -g serve@14.2.7

# Copy the built assets from the builder stage
COPY --from=builder /app/spa/dist ./content
# (Serving from a subdirectory like 'content' rather than root of /app for clarity)

# Expose the port 'serve' will listen on
EXPOSE 5173

# Command to serve the 'content' directory (which contains the SPA's 'dist' output)
# -s flag is important for single-page applications (SPA)
# -l flag specifies the listener port
CMD ["serve", "-s", "content", "-l", "5173"]
