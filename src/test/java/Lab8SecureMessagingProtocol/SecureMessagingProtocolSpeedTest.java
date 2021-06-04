package Lab8SecureMessagingProtocol;

import Lab5RandomNumberGenerator.RandomNumberGenerator;
import Lab7MutualAuthenticationProtocol.*;

import java.util.ArrayList;
import java.util.List;

public class SecureMessagingProtocolSpeedTest {
    public static void speedTestForExchangeMessages(UserOfTransmissionProtocol sender, UserOfTransmissionProtocol receiver, List<byte[]> messages) {
        SecureMessagingProtocol secureMessagingProtocol = new SecureMessagingProtocol(sender, receiver);
        long start = System.currentTimeMillis();
        secureMessagingProtocol.exchangeMessages(messages);
        System.out.println("На обмен " + messages.size() + " сообщениями затрачено: " + (System.currentTimeMillis() - start) / 1000 + " с");
    }

    public static void main(String[] args) {
        List<byte[]> messages = new ArrayList<>();
        RandomNumberGenerator randomNumberGenerator = new RandomNumberGenerator();
        for (int i = 0; i < 2000; i++) {
            byte[] message = randomNumberGenerator.generateRandomBytes(100 + i % 401);
            messages.add(message);
        }
        UserOfTransmissionProtocol sender = new UserOfNeedhamSchroederProtocol("Alice", new RandomNumberGenerator().generateRandomBytes(32), UserRole.INITIATOR);
        UserOfTransmissionProtocol receiver = new UserOfNeedhamSchroederProtocol("Bob", new RandomNumberGenerator().generateRandomBytes(32), UserRole.PRETENDER);
        System.out.println("Тестирование протокола с доверенной третьей стороной:");
        speedTestForExchangeMessages(sender, receiver, messages);
        sender = new UserOfSecureRemotePasswordProtocol("Alice", new RandomNumberGenerator().generateRandomBytes(32), UserRole.INITIATOR);
        receiver = new UserOfSecureRemotePasswordProtocol("Bob", new RandomNumberGenerator().generateRandomBytes(32), UserRole.PRETENDER);
        System.out.println("Тестирование протокола без доверенной третьей стороны:");
        speedTestForExchangeMessages(sender, receiver, messages);
    }
}
