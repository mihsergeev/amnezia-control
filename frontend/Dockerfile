FROM node:26-alpine AS build

WORKDIR /build
COPY package.json package-lock.json ./
RUN npm ci
COPY . .
RUN npm run build

FROM nginx:1.31.9-alpine3.24@sha256:90b6bd2aec278b16b98221d64deb1d6d35d164567f507ab0716e6053878315aa

# Apply security updates that landed in Alpine after the image was built.
RUN apk add --no-cache --upgrade 'libcrypto3>=3.5.9-r1' 'libssl3>=3.5.9-r1' 'libxslt>=1.1.43-r4' 'zlib>=1.4-r0'

COPY nginx.conf /etc/nginx/conf.d/default.conf
COPY --from=build /build/dist /usr/share/nginx/html
EXPOSE 80
