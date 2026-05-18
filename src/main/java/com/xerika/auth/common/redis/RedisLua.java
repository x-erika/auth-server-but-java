package com.xerika.auth.common.redis;

import io.quarkus.redis.datasource.RedisDataSource;
import io.vertx.mutiny.redis.client.Response;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;

import java.util.List;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;

@ApplicationScoped
public class RedisLua {

    public static final String GET_AND_DEL =
        "local v = redis.call('GET', KEYS[1]) " +
        "if v then redis.call('DEL', KEYS[1]) end " +
        "return v";

    public static final String INCR_AND_EXPIRE =
        "local n = redis.call('INCR', KEYS[1]) " +
        "if n == 1 then redis.call('EXPIRE', KEYS[1], ARGV[1]) end " +
        "return n";

    public static final String HGETALL_AND_DEL =
        "local v = redis.call('HGETALL', KEYS[1]) " +
        "if #v > 0 then redis.call('DEL', KEYS[1]) end " +
        "return v";

    @Inject
    RedisDataSource redis;

    private final ConcurrentMap<String, String> shaCache = new ConcurrentHashMap<>();

    public Response eval(String script, List<String> keys, List<String> args) {
        String sha = shaCache.computeIfAbsent(script, this::scriptLoad);
        try {
            return redis.execute("EVALSHA", buildArgs(sha, keys, args));
        } catch (RuntimeException e) {
            if (isNoScript(e)) {
                String reloaded = scriptLoad(script);
                shaCache.put(script, reloaded);
                return redis.execute("EVALSHA", buildArgs(reloaded, keys, args));
            }
            throw e;
        }
    }

    private String scriptLoad(String script) {
        Response r = redis.execute("SCRIPT", "LOAD", script);
        return r.toString();
    }

    private static boolean isNoScript(Throwable e) {
        Throwable cur = e;
        while (cur != null) {
            String msg = cur.getMessage();
            if (msg != null && msg.contains("NOSCRIPT")) {
                return true;
            }
            cur = cur.getCause();
        }
        return false;
    }

    private static String[] buildArgs(String shaOrScript, List<String> keys, List<String> args) {
        String[] out = new String[2 + keys.size() + args.size()];
        out[0] = shaOrScript;
        out[1] = Integer.toString(keys.size());
        int i = 2;
        for (String k : keys) {
            out[i++] = k;
        }
        for (String a : args) {
            out[i++] = a;
        }
        return out;
    }
}
