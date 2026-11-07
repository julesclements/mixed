# 1. Base Image
FROM node:26-slim

# 2. Working Directory
WORKDIR /usr/src/app

# 3. Copy the manifest and patched lockfile for reproducible installs.
COPY package.json package-lock.json ./

# 4. Install only production dependencies from the lockfile.
RUN npm ci --omit=dev

# 5. Copy Application Code
# Copy server.js and any other files like .env.example (though .env itself shouldn't be copied)
COPY . .
# More specific copy if preferred:
# COPY server.js .
# COPY .env.example .
# Ensure that if you have other subdirectories or files needed by the server, they are copied too.

# 6. Expose Port
# This should match the BFF_PORT your application listens on.
# The actual port mapping is done when running the container (e.g., with docker run -p).
EXPOSE 3001

# 7. Command
# Use npm start script which is "node server.js"
CMD [ "npm", "start" ]
