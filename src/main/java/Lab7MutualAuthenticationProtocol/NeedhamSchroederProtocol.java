package Lab7MutualAuthenticationProtocol;

import Lab4EncryptionModes.EncryptionMode;
import Lab5RandomNumberGenerator.RandomNumberGenerator;

import static Utils.CommonUtils.convertByteArrayToLong;

public class NeedhamSchroederProtocol {
    public static boolean authenticateTwoUsers(User initiator, User secondUser, TrustedServer server) {
        if (initiator.getUserRole() == secondUser.getUserRole())
            return false;
        else {
            byte[][] serverResponse = initiator.sendRequestForSessionKey(server, secondUser.getName());
            boolean serverResponseCheck = initiator.verifyTrustedServerResponse(serverResponse, secondUser.getName());
            if (!serverResponseCheck)
                return false;
            boolean initiatorSessionKeyCheck = initiator.getSessionKey(serverResponse[0], secondUser.getName());
            if (!initiatorSessionKeyCheck)
                return false;
            boolean secondUserSessionKeyCheck = secondUser.getSessionKey(serverResponse[1], initiator.getName());
            if (!secondUserSessionKeyCheck)
                return false;
            RandomNumberGenerator randomNumberGenerator = new RandomNumberGenerator();
            byte[] randomNumberBytes = randomNumberGenerator.generateRandomBytes(8);
            long secondUserIdentifier = convertByteArrayToLong(randomNumberBytes);
            byte[] encryptedIdentifier = secondUser.encryptMessageWithSessionKey(randomNumberBytes, EncryptionMode.ECB);
            byte[] decryptedIdentifier = initiator.decryptMessageWithSessionKey(encryptedIdentifier, EncryptionMode.ECB);
            long initiatorResponse = convertByteArrayToLong(decryptedIdentifier) - 1;
            return secondUserIdentifier - 1 == initiatorResponse;
        }
    }

    public static void main(String[] args) {
        User alice = new User("Alice", new RandomNumberGenerator().generateRandomBytes(32), UserRole.INITIATOR);
        User bob = new User("Bob", new RandomNumberGenerator().generateRandomBytes(32), UserRole.SECOND_USER);
        TrustedServer trustedServer = new TrustedServer();
        trustedServer.registerUser(alice.getName(), alice.getUserKey());
        trustedServer.registerUser(bob.getName(), bob.getUserKey());
        System.out.println(authenticateTwoUsers(alice, bob, trustedServer));
    }
}
