# Stage 1: Build the static assets for the SPA
FROM node:20-slim AS builder

ARG VITE_STAFF_CLIENT_ID=your_staff_id_here
ARG VITE_CUSTOMER_CLIENT_ID=your_customer_id_here
ARG VITE_PING_BASE_URL=https://localhost:9031/as/authorization.oauth2

WORKDIR /app/spa

# Copy package.json and package-lock.json (if available)
COPY package*.json ./

# Install dependencies
RUN npm install

# Copy the rest of the SPA application source code
COPY . .

# Build the application
# The output will be in the /app/spa/dist directory
ENV VITE_STAFF_CLIENT_ID=${VITE_STAFF_CLIENT_ID}
ENV VITE_CUSTOMER_CLIENT_ID=${VITE_CUSTOMER_CLIENT_ID}
ENV VITE_PING_BASE_URL=${VITE_PING_BASE_URL}
RUN npm run build

# Stage 2: Serve the static assets from the 'dist' directory
FROM node:20-alpine AS runner

WORKDIR /app

# Install 'serve' to serve static files
RUN npm install -g serve

# Copy the built assets from the builder stage
COPY --from=builder /app/spa/dist ./content
# (Serving from a subdirectory like 'content' rather than root of /app for clarity)

# Expose the port 'serve' will listen on
EXPOSE 5173

# Command to serve the 'content' directory (which contains the SPA's 'dist' output)
# -s flag is important for single-page applications (SPA)
# -l flag specifies the listener port
CMD ["serve", "-s", "content", "-l", "5173"]
