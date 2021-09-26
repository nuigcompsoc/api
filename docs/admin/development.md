# Developing the CompSoc API & Frontend

## Routing
As the API and Frontend run on the same domain for CORS and cookies reasons, we have have to use a router that will route all v1 requests to the API and the rest to the frontend. Setup for this router is quite simple as Traefik does all the certificate signing and logging for us.

### Setting Up Traefik

#### Making the docker compose file

    version: "3.3"

    services:
    traefik:
        image: traefik:v2.5
        restart: always
        container_name: traefik
        ports:
        - "80:80" # <== http
        - "443:443" # <== https
        command:
        - --log.level=DEBUG # <== Setting the level of the logs from traefik
        - --providers.file.directory=/dynamic # <== Referring to a dynamic configuration file
        - --providers.file.watch=true # allow auto update from file change
        - --entrypoints.web.address=:80
        - --entrypoints.web.http.redirections.entryPoint.to=websecure
        - --entrypoints.web.http.redirections.entryPoint.scheme=https
        - --entrypoints.web.http.redirections.entrypoint.permanent=true
        - --entrypoints.websecure.address=:443
        volumes:
        - /var/run/docker.sock:/var/run/docker.sock # <== Volume for docker admin
        - ./dynamic:/dynamic # <== Volume for dynamic conf file
        networks:
        - transit-public

    networks:
    transit-public:
        external: true

Put this file anywhere, I've it placed in /opt/traefik. Just make sure its somewhere that you remember and not in the repo.

#### Making the dynamic configuration

    conor@Shaw-Smith:/opt/traefik$ mkdir dynamic
    conor@Shaw-Smith:/opt/traefik$ nano dash.yml
    http:
        # Add the router
        routers:
            dash-api:
                entryPoints: websecure
                tls: true
                service: dash-api
                rule: Host(`dash.compsoc.ie`) && PathPrefix(`/v1`)
            dash:
                entryPoints: websecure
                tls: true
                service: dash
                rule: Host(`dash.compsoc.ie`)

        # Add the service
        services:
            dash:
                loadBalancer:
                    servers:
                    - url: "http://YOUR LOCAL NETWORK ADDRESS (192.168.X.X):3000"
                    passHostHeader: true
            dash-api:
                loadBalancer:
                    servers:
                    - url: "http://YOUR LOCAL NETWORK ADDRESS (192.168.X.X):3001"
                    passHostHeader: true

#### Run it!

    conor@Shaw-Smith:/opt/traefik$ docker-compose up -d

## Running the API

    conor@Shaw-Smith:~/api$ go run cmd/main.go
