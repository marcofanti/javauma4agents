# Builds the Java shim and a runtime that can also drive it with the pinned
# upstream Python MCP client check (conformance/upstream/.../test_shim.py), which
# the compose shim-test profile runs. Python client versions are pinned exactly.
FROM maven:3.9-eclipse-temurin-26 AS build
WORKDIR /src
COPY pom.xml .
COPY lib lib
COPY mcp mcp
COPY services services
COPY clients clients
RUN --mount=type=cache,target=/root/.m2 mvn -q -pl clients/agent-shim -am package -DskipTests

FROM eclipse-temurin:26-jre
RUN apt-get update \
    && apt-get install -y --no-install-recommends python3 python3-pip \
    && rm -rf /var/lib/apt/lists/* \
    && pip3 install --break-system-packages --no-cache-dir 'mcp==2.3.0' 'httpx==0.28.1' 'pyjwt[crypto]==2.15.1' 'cryptography==50.0.2'
COPY --from=build /src/clients/agent-shim/target/shim.jar /app/shim.jar
CMD ["java", "-jar", "/app/shim.jar"]
