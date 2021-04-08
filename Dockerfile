FROM node:14

WORKDIR /usr/src/app

ARG ZARYA_PORT
ENV ZARYA_PORT "$ZARYA_PORT"

ARG HASURA_GRAPHQL_ADMIN_SECRET
ENV HASURA_GRAPHQL_ADMIN_SECRET "$HASURA_GRAPHQL_ADMIN_SECRET"

ARG ENCRYPTION_KEY
ENV ENCRYPTION_KEY "$ENCRYPTION_KEY"

COPY ["package.json", "package-lock.json*", "npm-shrinkwrap.json*", "./"]

RUN npm install --production --silent && mv node_modules ../

COPY . .

EXPOSE "$PORT"

RUN npm install -g nodemon

CMD npm start