package com.xerika.auth.common.redis;

public final class RedisKeys {

    private RedisKeys() {
    }

    private static final String AUTHCODE = "authcode:";
    private static final String DEVICE_DC = "device:dc:";
    private static final String DEVICE_UC = "device:uc:";
    private static final String PENDING_AUTH = "pending:";
    private static final String SESSION = "session:";
    private static final String CLIENT = "client:";
    private static final String RL_LOGIN_EMAIL = "rl:login:email:";
    private static final String RL_LOGIN_IP = "rl:login:ip:";
    private static final String RL_SIGNUP_IP = "rl:signup:ip:";
    private static final String RL_VERIFY_EMAIL_IP = "rl:verify-email:ip:";
    private static final String RL_DEVICE_AUTH = "rl:device-auth:";

    public static String authCode(String code) {
        return AUTHCODE + code;
    }

    public static String deviceByCode(String deviceCode) {
        return DEVICE_DC + deviceCode;
    }

    public static String deviceByUserCode(String userCode) {
        return DEVICE_UC + userCode;
    }

    public static String pendingAuth(String state) {
        return PENDING_AUTH + state;
    }

    public static String session(String tokenHash) {
        return SESSION + tokenHash;
    }

    public static String client(String clientId) {
        return CLIENT + clientId;
    }

    public static String rlLoginEmail(String email) {
        return RL_LOGIN_EMAIL + email;
    }

    public static String rlLoginIp(String ip) {
        return RL_LOGIN_IP + ip;
    }

    public static String rlSignupIp(String ip) {
        return RL_SIGNUP_IP + ip;
    }

    public static String rlVerifyEmailIp(String ip) {
        return RL_VERIFY_EMAIL_IP + ip;
    }

    public static String rlDeviceAuth(String clientId) {
        return RL_DEVICE_AUTH + clientId;
    }
}
