FROM maven:3.9-eclipse-temurin-21 AS builder

WORKDIR /app

COPY .mvn/ .mvn/
COPY mvnw pom.xml ./
RUN ./mvnw -B -q -DskipTests dependency:go-offline

COPY src ./src
RUN ./mvnw -B -q -DskipTests package

FROM eclipse-temurin:21-jre AS runtime

RUN apt-get update && \
    apt-get install -y --no-install-recommends curl && \
    rm -rf /var/lib/apt/lists/*

COPY --from=builder /app/target/quarkus-app/lib/      /deployments/lib/
COPY --from=builder /app/target/quarkus-app/*.jar     /deployments/
COPY --from=builder /app/target/quarkus-app/app/      /deployments/app/
COPY --from=builder /app/target/quarkus-app/quarkus/  /deployments/quarkus/

ENV \
    JAVA_OPTS_APPEND="-Xms512m -Xmx512m -XX:+AlwaysPreTouch -Dquarkus.http.host=0.0.0.0 -Djava.util.logging.manager=org.jboss.logmanager.LogManager"

EXPOSE 8080

ENTRYPOINT ["sh", "-c", "exec java ${JAVA_OPTS_APPEND} -jar /deployments/quarkus-run.jar"]
