# Builds the Java shim and a runtime that can also drive it with the scripted
# Python MCP client (test_shim.py) — used by the compose shim-test profile.
FROM maven:3.9-eclipse-temurin-25 AS build
WORKDIR /src
COPY pom.xml .
COPY lib lib
COPY mcp mcp
COPY services services
COPY clients clients
RUN --mount=type=cache,target=/root/.m2 mvn -q -pl clients/agent-shim -am package -DskipTests

FROM eclipse-temurin:25-jre
RUN apt-get update \
    && apt-get install -y --no-install-recommends python3 python3-pip \
    && rm -rf /var/lib/apt/lists/* \
    && pip3 install --break-system-packages --no-cache-dir 'mcp>=1.13' httpx 'pyjwt[crypto]'
COPY --from=build /src/clients/agent-shim/target/shim.jar /app/shim.jar
ENV SHIM_CMD="java -jar /app/shim.jar"
CMD ["java", "-jar", "/app/shim.jar"]
