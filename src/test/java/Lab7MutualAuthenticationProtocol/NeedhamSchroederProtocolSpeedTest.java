package Lab7MutualAuthenticationProtocol;

import Lab5RandomNumberGenerator.RandomNumberGenerator;

import static Lab7MutualAuthenticationProtocol.NeedhamSchroederProtocol.authenticateTwoUsers;

public class NeedhamSchroederProtocolSpeedTest {
    public static void speedTestForAuthenticateTwoUsers() {
        User alice = new User("Alice", new RandomNumberGenerator().generateRandomBytes(32), UserRole.INITIATOR);
        User bob = new User("Bob", new RandomNumberGenerator().generateRandomBytes(32), UserRole.SECOND_USER);
        TrustedServer trustedServer = new TrustedServer();
        trustedServer.registerUser(alice.getName(), alice.getUserKey());
        trustedServer.registerUser(bob.getName(), bob.getUserKey());
        long start = System.currentTimeMillis();
        for (int i = 0; i < 10000; i++) {
            authenticateTwoUsers(alice, bob, trustedServer);
        }
        System.out.println("На 10000 аутентификаций затрачено: " + ((System.currentTimeMillis() - start) / 1000) + " c");
    }

    public static void main(String[] args) {
        speedTestForAuthenticateTwoUsers();
    }
}
