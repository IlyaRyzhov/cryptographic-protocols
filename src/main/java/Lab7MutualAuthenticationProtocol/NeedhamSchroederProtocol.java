package Lab7MutualAuthenticationProtocol;

import Lab4EncryptionModes.EncryptionMode;
import Lab5RandomNumberGenerator.RandomNumberGenerator;

import static Utils.TransmissionChannelUtils.readMessageFromTransmissionChannel;
import static Utils.TransmissionChannelUtils.writeMessageToTransmissionChannel;
import static Lab7MutualAuthenticationProtocol.TrustedServer.sendResponseForSessionKeyWithInitiatorIdentifier;
import static Utils.CommonUtils.convertByteArrayToLong;

public class NeedhamSchroederProtocol implements AuthenticationProtocol {
    private int numberOfUnsuccessfulAttempts;

    /**
     * Производит аутентификацию пользователей с использованием доверенной третьей стороны
     *
     * @param initiator инициирующий аутентификацию пользователь
     * @param pretender пользователь, с которым собирается начать информационный обмен инициирующий пользователь
     * @return true - если процедура аутентификации прошла успешна, false - в противном случае.
     * @throws IllegalStateException в случае 10 неудачных попыток аутентификации подряд
     * @author Ilya Ryzhov
     */
    private boolean authenticateTwoUsersWithTrustedServer(UserOfProtocolWithTrustedServer initiator, UserOfProtocolWithTrustedServer pretender) {
        if (numberOfUnsuccessfulAttempts == 10) {
            numberOfUnsuccessfulAttempts = 0;
            throw new IllegalStateException("Превышено количество неудачных попыток");
        }
        if (initiator.getUserRole() != UserRole.INITIATOR || initiator.getUserRole() == pretender.getUserRole()) {
            return false;
        } else {
            initiator.sendRequestForSessionKey(pretender.getName());
            byte[][] serverResponse = sendResponseForSessionKeyWithInitiatorIdentifier(initiator);
            writeMessageToTransmissionChannel(serverResponse[0]);
            boolean serverResponseCheck = initiator.verifyTrustedServerResponse(pretender.getName());
            if (!serverResponseCheck) {
                numberOfUnsuccessfulAttempts++;
                return false;
            }
            writeMessageToTransmissionChannel(serverResponse[1]);
            boolean pretenderUserSessionKeyCheck = pretender.getSessionKeyFromMessage(readMessageFromTransmissionChannel(), initiator.getName());
            if (!pretenderUserSessionKeyCheck) {
                numberOfUnsuccessfulAttempts++;
                return false;
            }
            RandomNumberGenerator randomNumberGenerator = new RandomNumberGenerator();
            byte[] randomNumberBytes = randomNumberGenerator.generateRandomBytes(8);
            long pretenderUserIdentifier = convertByteArrayToLong(randomNumberBytes);
            byte[] encryptedIdentifier = pretender.encryptMessageWithSessionKey(randomNumberBytes, EncryptionMode.ECB);
            writeMessageToTransmissionChannel(encryptedIdentifier);
            byte[] decryptedIdentifier = initiator.decryptMessageWithSessionKey(readMessageFromTransmissionChannel(), EncryptionMode.ECB);
            long initiatorResponse = convertByteArrayToLong(decryptedIdentifier) - 1;
            boolean authenticationStatus = pretenderUserIdentifier - 1 == initiatorResponse;
            if (authenticationStatus)
                numberOfUnsuccessfulAttempts = 0;
            else numberOfUnsuccessfulAttempts++;
            return authenticationStatus;
        }
    }

    @Override
    public boolean authenticateTwoUsers(UserOfTransmissionProtocol initiator, UserOfTransmissionProtocol pretender) {
        return authenticateTwoUsersWithTrustedServer((UserOfProtocolWithTrustedServer) initiator, (UserOfProtocolWithTrustedServer) pretender);
    }
}
