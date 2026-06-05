set -e

PG_VERSION=17
PG_HBA=/etc/postgresql/${PG_VERSION}/main/pg_hba.conf
PG_DATA=/var/lib/postgresql/${PG_VERSION}/main
INIT_MARKER=/var/lib/postgresql/.initialized

mkdir -p /var/run/postgresql
chown postgres:postgres /var/run/postgresql

chown -R postgres:postgres /var/lib/postgresql

if [ ! -f "$INIT_MARKER" ]; then
    echo "[start.sh] first-boot postgres init…"
    pg_ctlcluster ${PG_VERSION} main start

    for i in $(seq 1 30); do
        if pg_isready -h /var/run/postgresql -U postgres >/dev/null 2>&1; then
            break
        fi
        sleep 1
    done

    gosu postgres psql -v ON_ERROR_STOP=1 -c "ALTER USER postgres WITH PASSWORD '${POSTGRES_PASSWORD}';"
    gosu postgres psql -v ON_ERROR_STOP=1 -c "CREATE DATABASE \"${POSTGRES_DB}\";"

    sed -i 's|^host\s\+all\s\+all\s\+127\.0\.0\.1/32\s\+.*|host all all 127.0.0.1/32 md5|' "$PG_HBA"
    sed -i 's|^host\s\+all\s\+all\s\+::1/128\s\+.*|host all all ::1/128 md5|' "$PG_HBA"

    pg_ctlcluster ${PG_VERSION} main stop

    touch "$INIT_MARKER"
    echo "[start.sh] postgres init done"
fi

sed -i "s|^# *requirepass .*|requirepass ${REDIS_PASS}|" /etc/redis/redis.conf
sed -i "s|^requirepass .*|requirepass ${REDIS_PASS}|" /etc/redis/redis.conf
sed -i 's|^bind 127\.0\.0\.1.*|bind 0.0.0.0 ::1|' /etc/redis/redis.conf
sed -i 's|^daemonize yes|daemonize no|' /etc/redis/redis.conf
sed -i 's|^supervised .*|supervised no|' /etc/redis/redis.conf

exec /usr/bin/supervisord -n -c /etc/supervisor/supervisord.conf
