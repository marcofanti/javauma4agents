FROM maven:3.9-eclipse-temurin-21 AS build
WORKDIR /src
COPY pom.xml .
COPY lib lib
COPY mcp mcp
COPY services services
COPY clients clients
RUN --mount=type=cache,target=/root/.m2 mvn -q -pl mcp/alice-vault -am package -DskipTests

FROM eclipse-temurin:21-jre
RUN apt-get update && apt-get install -y --no-install-recommends curl \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY --from=build /src/mcp/alice-vault/target/alice-vault.jar app.jar
EXPOSE 9020
CMD ["java", "-jar", "app.jar"]
