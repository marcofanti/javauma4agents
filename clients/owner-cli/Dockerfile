FROM maven:3.9-eclipse-temurin-26 AS build
WORKDIR /src
COPY pom.xml .
COPY lib lib
COPY mcp mcp
COPY services services
COPY clients clients
RUN --mount=type=cache,target=/root/.m2 mvn -q -pl clients/owner-cli -am package -DskipTests

FROM eclipse-temurin:26-jre
COPY --from=build /src/clients/owner-cli/target/owner.jar /app/owner.jar
ENTRYPOINT ["java", "-jar", "/app/owner.jar"]
