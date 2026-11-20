FROM maven:3.9-eclipse-temurin-26 AS build
WORKDIR /src
COPY pom.xml .
COPY lib lib
COPY mcp mcp
COPY services services
COPY clients clients
RUN --mount=type=cache,target=/root/.m2 mvn -q -pl services/alice-portal -am package -DskipTests

FROM eclipse-temurin:26-jre
RUN apt-get update && apt-get install -y --no-install-recommends curl \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY --from=build /src/services/alice-portal/target/alice-portal.jar app.jar
# The pinned upstream SPA, unchanged (make vendor-verify checks its blobs).
COPY conformance/upstream/services/alice-portal/static /app/static
COPY conformance/upstream/services/org-console/static /app/org-console-static
ENV STATIC_DIR=/app/static
EXPOSE 9010
CMD ["java", "-jar", "app.jar"]
