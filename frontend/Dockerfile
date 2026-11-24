# Base image by digest, so the CI scan and the release build use the same base.
FROM node:26-alpine@sha256:6bd9ab43c0ec0190ca7b2d193906cb8b7edf6e7f4afa43ddeccd6452710bffb5 AS build

WORKDIR /build
COPY package.json package-lock.json ./
# no install scripts: none of the dependencies needs one, and swagger-ui pulls a
# telemetry postinstall (@scarf/scarf)
RUN npm ci --ignore-scripts
COPY . .
RUN npm run build

FROM nginx:1.31.9-alpine3.24@sha256:fb4658584bd9a916ffb6f6e365f97c25cfdb2923801f551ea08356e695f14ff7

# Apply security updates that landed in Alpine after the image was built.
RUN apk add --no-cache --upgrade 'libcrypto3>=3.5.9-r1' 'libssl3>=3.5.9-r1' 'libxslt>=1.1.43-r4' 'zlib>=1.4-r0'

COPY nginx.conf /etc/nginx/conf.d/default.conf
COPY --from=build /build/dist /usr/share/nginx/html
EXPOSE 80
