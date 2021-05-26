package Lab7MutualAuthenticationProtocol;

import Lab4EncryptionModes.EncryptionMode;
import Lab5RandomNumberGenerator.RandomNumberGenerator;

import static Lab7MutualAuthenticationProtocol.TransmissionChannel.readMessageFromTransmissionChannel;
import static Lab7MutualAuthenticationProtocol.TransmissionChannel.writeMessageToTransmissionChannel;
import static Utils.CommonUtils.convertByteArrayToLong;

public class NeedhamSchroederProtocol {
    public static int numberOfUnsuccessfulAttempts = 0;

    /**
     * Производит аутентификацию пользователей
     *
     * @param initiator  инициирующий аутентификацию пользователь
     * @param secondUser пользователь, с которым собирается начать информационный обмен инициирующий пользователь
     * @param server     доверенная третья сторона(доверенный сервер)
     * @return true - если процедура аутентификации прошла успешна, false - в противном случае.
     * @throws IllegalStateException в случае 10 неудачных попыток аутентификации подряд
     * @author Ilya Ryzhov
     */
    public static boolean authenticateTwoUsers(User initiator, User secondUser, TrustedServer server) {
        if (numberOfUnsuccessfulAttempts == 10) {
            numberOfUnsuccessfulAttempts = 0;
            throw new IllegalStateException("Превышено количество неудачных попыток");
        }
        if (initiator.getUserRole() != UserRole.INITIATOR || initiator.getUserRole() == secondUser.getUserRole()) {
            return false;
        } else {
            initiator.sendRequestForSessionKey(secondUser.getName());
            byte[][] serverResponse = server.sendResponseForSessionKeyWithInitiatorIdentifier(initiator);
            writeMessageToTransmissionChannel(serverResponse[0]);
            boolean serverResponseCheck = initiator.verifyTrustedServerResponse(secondUser.getName());
            if (!serverResponseCheck) {
                numberOfUnsuccessfulAttempts++;
                return false;
            }
            writeMessageToTransmissionChannel(serverResponse[1]);
            boolean secondUserSessionKeyCheck = secondUser.getSessionKeyFromMessage(readMessageFromTransmissionChannel(), initiator.getName());
            if (!secondUserSessionKeyCheck) {
                numberOfUnsuccessfulAttempts++;
                return false;
            }
            RandomNumberGenerator randomNumberGenerator = new RandomNumberGenerator();
            byte[] randomNumberBytes = randomNumberGenerator.generateRandomBytes(8);
            long secondUserIdentifier = convertByteArrayToLong(randomNumberBytes);
            byte[] encryptedIdentifier = secondUser.encryptMessageWithSessionKey(randomNumberBytes, EncryptionMode.ECB);
            writeMessageToTransmissionChannel(encryptedIdentifier);
            byte[] decryptedIdentifier = initiator.decryptMessageWithSessionKey(readMessageFromTransmissionChannel(), EncryptionMode.ECB);
            long initiatorResponse = convertByteArrayToLong(decryptedIdentifier) - 1;
            boolean authenticationStatus = secondUserIdentifier - 1 == initiatorResponse;
            if (authenticationStatus)
                numberOfUnsuccessfulAttempts = 0;
            else numberOfUnsuccessfulAttempts++;
            return authenticationStatus;
        }
    }
}
