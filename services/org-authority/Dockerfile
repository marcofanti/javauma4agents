# Build context is the repo root (shared lib/).
FROM maven:3.9-eclipse-temurin-26 AS build
WORKDIR /src
COPY pom.xml .
COPY lib lib
COPY mcp mcp
COPY services services
COPY clients clients
COPY conformance/upstream/services/org-authority conformance/upstream/services/org-authority
RUN --mount=type=cache,target=/root/.m2 mvn -q -pl services/org-authority -am package -DskipTests

FROM eclipse-temurin:26-jre
RUN apt-get update && apt-get install -y --no-install-recommends curl \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY --from=build /src/services/org-authority/target/org-authority.jar app.jar
EXPOSE 9040
CMD ["java", "-jar", "app.jar"]
