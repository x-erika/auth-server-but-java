set -e

for i in $(seq 1 60); do
    if pg_isready -h localhost -p 5432 -U postgres >/dev/null 2>&1; then
        break
    fi
    sleep 1
done

exec java ${JAVA_OPTS_APPEND} -jar /deployments/quarkus-run.jar
