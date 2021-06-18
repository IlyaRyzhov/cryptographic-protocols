package mutualAuthenticationProtocol;

import randomNumberGenerator.RandomNumberGenerator;

public class AuthenticationProtocolSpeedTest {
    public static void speedTestForNeedhamShroederProtocol() {
        UserOfNeedhamSchroederProtocol alice = new UserOfNeedhamSchroederProtocol("Alice", new RandomNumberGenerator().generateRandomBytes(32), UserRole.INITIATOR);
        UserOfNeedhamSchroederProtocol bob = new UserOfNeedhamSchroederProtocol("Bob", new RandomNumberGenerator().generateRandomBytes(32), UserRole.PRETENDER);
        long start = System.currentTimeMillis();
        for (int i = 0; i < 100; i++) {
            alice.authenticatePretender(bob);
        }
        System.out.println("На 10000 аутентификаций затрачено: " + ((System.currentTimeMillis() - start) / 1000) + " c");
    }

    public static void speedTestForSecureRemotePasswordProtocol() {
        UserOfSecureRemotePasswordProtocol alice = new UserOfSecureRemotePasswordProtocol("Alice", new RandomNumberGenerator().generateRandomBytes(32), UserRole.INITIATOR);
        UserOfSecureRemotePasswordProtocol bob = new UserOfSecureRemotePasswordProtocol("Bob", new RandomNumberGenerator().generateRandomBytes(32), UserRole.PRETENDER);
        long start = System.currentTimeMillis();
        for (int i = 0; i < 100; i++) {
            alice.authenticatePretender(bob);
        }
        System.out.println("На 10000 аутентификаций затрачено: " + ((System.currentTimeMillis() - start) / 1000) + " c");
    }

    public static void main(String[] args) {
        speedTestForNeedhamShroederProtocol();
        speedTestForSecureRemotePasswordProtocol();
    }
}
