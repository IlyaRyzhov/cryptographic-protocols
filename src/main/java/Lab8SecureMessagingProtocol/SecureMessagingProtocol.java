package Lab8SecureMessagingProtocol;

import Lab5RandomNumberGenerator.RandomNumberGenerator;
import Lab7MutualAuthenticationProtocol.UserOfTransmissionProtocol;

import java.util.Arrays;
import java.util.List;

import static Lab4EncryptionModes.EncryptionMode.ECB;

public class SecureMessagingProtocol {
    private int numberOfExchangedMessage;
    private final UserOfTransmissionProtocol sender;
    private final UserOfTransmissionProtocol receiver;
    private boolean isExchangeInitialized;

    public SecureMessagingProtocol(UserOfTransmissionProtocol sender, UserOfTransmissionProtocol receiver) {
        this.sender = sender;
        this.receiver = receiver;
    }

    /**
     * Отправляет сообщения от sender к receiver по протоколу защищенной передачи сообщений
     *
     * @param messages отправляемые сообщения
     * @author Ilya Ryzhov
     */
    public void exchangeMessages(List<byte[]> messages) {
        for (byte[] message : messages) {
            int numberOfUnsuccessfulAttempts = 0;
            while (true) {
                if (numberOfUnsuccessfulAttempts == 10)
                    throw new IllegalStateException("Не удалось отправить сообщение");
                boolean isExchangeResultSuccess = exchangeMessage(message);
                if (isExchangeResultSuccess)
                    break;
                else numberOfUnsuccessfulAttempts++;
            }
        }
    }

    private boolean exchangeMessage(byte[] message) {
        if (!isExchangeInitialized) {
            isExchangeInitialized = initializeExchange();
        }
        if (!isExchangeInitialized) {
            throw new IllegalStateException("Не удалось инициализировать обмен сообщениями");
        }
        byte[] messageSignature = sender.getBonehLynnShachamSignatureWithUserKey().getSignature(message);
        byte[] messageWithSignature = Arrays.copyOf(messageSignature, messageSignature.length + message.length);
        System.arraycopy(message, 0, messageWithSignature, messageSignature.length, message.length);
        sender.sendMessage(sender.encryptMessageWithSessionKey(messageWithSignature));
        numberOfExchangedMessage++;
        receiver.receiveMessage();
        receiver.setReceivedMessage(receiver.decryptMessageWithSessionKey(receiver.getReceivedMessage()));
        if (receiver.getReceivedMessage() == null)
            return false;
        receiver.getSignatureFromReceivedMessage();
        if (numberOfExchangedMessage == 1000) {
            isExchangeInitialized = false;
            initializeExchange();
            numberOfExchangedMessage = 0;
        }
        return receiver.getMessageFromReceivedMessage(sender.getBonehLynnShachamSignatureWithUserKey().getPublicKey());
    }

    private boolean initializeExchange() {
        sender.authenticatePretender(receiver);
        int numberOfAttemptsOfInitialization = 0;
        while (true) {
            if (numberOfAttemptsOfInitialization == 10)
                return false;
            boolean receiverInitializationVectorSuccessStatus = exchangeInitializationVector();
            if (receiverInitializationVectorSuccessStatus) {
                byte[] initializationVector = receiver.getInitializationVector();
                byte[] receiverSignature = receiver.getBonehLynnShachamSignatureWithUserKey().getSignature(initializationVector);
                byte[] message = Arrays.copyOfRange(receiverSignature, 0, receiverSignature.length + initializationVector.length);
                System.arraycopy(initializationVector, 0, message, receiverSignature.length, initializationVector.length);
                receiver.sendMessage(receiver.encryptMessageWithSessionKey(message, ECB));
                sender.receiveMessage();
                sender.setReceivedMessage(sender.decryptMessageWithSessionKey(sender.getReceivedMessage(), ECB));
                sender.getSignatureFromReceivedMessage();
                boolean senderInitializationVectorSuccessStatus = sender.getInitializationVectorFromReceivedMessage(receiver.getBonehLynnShachamSignatureWithUserKey().getPublicKey());
                if (senderInitializationVectorSuccessStatus)
                    break;
            } else {
                numberOfAttemptsOfInitialization++;
            }
        }
        receiver.initializeCipherWithSessionKey();
        sender.initializeCipherWithSessionKey();
        return true;
    }

    private boolean exchangeInitializationVector() {
        RandomNumberGenerator randomNumberGenerator = new RandomNumberGenerator();
        byte[] initializationVector = randomNumberGenerator.generateRandomBytes(16);
        byte[] initializationVectorSignature = sender.getBonehLynnShachamSignatureWithUserKey().getSignature(initializationVector);
        byte[] message = Arrays.copyOf(initializationVectorSignature, initializationVector.length + initializationVectorSignature.length);
        System.arraycopy(initializationVector, 0, message, initializationVectorSignature.length, initializationVector.length);
        sender.sendMessage(sender.encryptMessageWithSessionKey(message, ECB));
        sender.setInitializationVector(initializationVector);
        receiver.receiveMessage();
        receiver.setReceivedMessage(receiver.decryptMessageWithSessionKey(receiver.getReceivedMessage(), ECB));
        receiver.getSignatureFromReceivedMessage();
        return receiver.getInitializationVectorFromReceivedMessage(sender.getBonehLynnShachamSignatureWithUserKey().getPublicKey());
    }
}
