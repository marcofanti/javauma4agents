FROM maven:3.9-eclipse-temurin-25 AS build
WORKDIR /src
COPY pom.xml .
COPY lib lib
COPY mcp mcp
COPY services services
COPY clients clients
RUN --mount=type=cache,target=/root/.m2 mvn -q -pl clients/demo-driver -am package -DskipTests

FROM eclipse-temurin:25-jre
WORKDIR /driver
COPY --from=build /src/clients/demo-driver/target/driver.jar /app/driver.jar
ENTRYPOINT ["java", "-jar", "/app/driver.jar", "--cacert", "/driver/rootCA.pem"]
