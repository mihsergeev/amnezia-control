FROM node:26-alpine AS build

WORKDIR /build
COPY package.json package-lock.json ./
RUN npm ci
COPY . .
RUN npm run build

FROM nginx:1.31-alpine

# The upstream image can lag behind Alpine's libxslt and zlib security fixes.
RUN apk add --no-cache --upgrade 'libxslt>=1.1.43-r4' 'zlib>=1.4-r0'

COPY nginx.conf /etc/nginx/conf.d/default.conf
COPY --from=build /build/dist /usr/share/nginx/html
EXPOSE 80
