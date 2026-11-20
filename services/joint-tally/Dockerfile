# Build context is the repo root (shared lib/).
FROM maven:3.9-eclipse-temurin-26 AS build
WORKDIR /src
COPY pom.xml .
COPY lib lib
COPY mcp mcp
COPY services services
COPY clients clients
RUN --mount=type=cache,target=/root/.m2 mvn -q -pl services/joint-tally -am package -DskipTests

FROM eclipse-temurin:26-jre
RUN apt-get update && apt-get install -y --no-install-recommends curl \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY --from=build /src/services/joint-tally/target/joint-tally.jar app.jar
EXPOSE 9060
CMD ["java", "-jar", "app.jar"]
