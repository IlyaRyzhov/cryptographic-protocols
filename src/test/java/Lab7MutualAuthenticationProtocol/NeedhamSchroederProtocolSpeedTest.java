package Lab7MutualAuthenticationProtocol;

import Lab5RandomNumberGenerator.RandomNumberGenerator;

public class NeedhamSchroederProtocolSpeedTest {
    public static void speedTestForAuthenticateTwoUsers() {
        UserOfProtocolWithTrustedServer alice = new UserOfProtocolWithTrustedServer("Alice", new RandomNumberGenerator().generateRandomBytes(32), UserRole.INITIATOR);
        UserOfProtocolWithTrustedServer bob = new UserOfProtocolWithTrustedServer("Bob", new RandomNumberGenerator().generateRandomBytes(32), UserRole.PRETENDER);
        long start = System.currentTimeMillis();
        for (int i = 0; i < 10000; i++) {
            alice.authenticatePretender(bob);
        }
        System.out.println("На 10000 аутентификаций затрачено: " + ((System.currentTimeMillis() - start) / 1000) + " c");
    }

    public static void main(String[] args) {
        speedTestForAuthenticateTwoUsers();
    }
}
