package Lab3DigitalSignatureAlgorithm;

import Lab2HashAlgorithm.BlueMidnightWish;
import Lab2HashAlgorithm.BlueMidnightWishDigestSize;
import Lab5RandomNumberGenerator.RandomNumberGenerator;

import java.io.*;

import static Lab2HashAlgorithm.BlueMidnightWishDigestSize.BLUE_MIDNIGHT_WISH_512;

public class BonehLynnShachamSignatureSpeedTest {
    public static void speedTestForArbitraryBlocksOfSigningMessage(int numberOfBlocks) {
        byte[] messageBlock = new byte[128];
        byte[] key = new RandomNumberGenerator().generateRandomBytes(23);
        BonehLynnShachamSignature bonehLynnShachamSignature = new BonehLynnShachamSignature(key, new BlueMidnightWish(BLUE_MIDNIGHT_WISH_512));
        byte[] signature;
        long start = System.currentTimeMillis();
        for (int i = 0; i < numberOfBlocks; i++) {
            signature = bonehLynnShachamSignature.getSignature(messageBlock);
            bonehLynnShachamSignature.verifySignature(messageBlock, signature);
        }
        System.out.println("На подпись и проверку подписи " + numberOfBlocks + " блоков длины 128 байт затрачено: " + (System.currentTimeMillis() - start) + " мс");
    }

    public static void speedTestForArbitraryOfSigningFiles(File file) {
        try (BufferedInputStream bufferedInputStream = new BufferedInputStream(new FileInputStream(file))) {
            byte[] key = new RandomNumberGenerator().generateRandomBytes(23);
            BonehLynnShachamSignature bonehLynnShachamSignature = new BonehLynnShachamSignature(key, new BlueMidnightWish(BLUE_MIDNIGHT_WISH_512));
            byte[] message = bufferedInputStream.readAllBytes();
            long start = System.currentTimeMillis();
            byte[] signature = bonehLynnShachamSignature.getSignature(message);
            bonehLynnShachamSignature.verifySignature(message, signature);
            System.out.println("На подпись и проверку подписи файла размером " + file.length() + " байтов затрачено:" + (System.currentTimeMillis() - start) + " мс");
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    public static void speedTestForArbitraryBlocksOfSigningMessageWithChangingKey(int numberOfBlocks, int keyChangeFrequency) {
        byte[] messageBlock = new byte[128];
        RandomNumberGenerator randomNumberGenerator = new RandomNumberGenerator();
        byte[] key = randomNumberGenerator.generateRandomBytes(23);
        BonehLynnShachamSignature bonehLynnShachamSignature = new BonehLynnShachamSignature(key, new BlueMidnightWish(BLUE_MIDNIGHT_WISH_512));
        byte[] signature;
        long start = System.currentTimeMillis();
        for (int i = 0; i < numberOfBlocks; i++) {
            if (i % keyChangeFrequency == 0 && i != 0) {
                key = randomNumberGenerator.generateRandomBytes(23);
                bonehLynnShachamSignature.setSecretKey(key);
            }
            signature = bonehLynnShachamSignature.getSignature(messageBlock);
            bonehLynnShachamSignature.verifySignature(messageBlock, signature);
        }
        System.out.println("На подпись и проверку подписи " + numberOfBlocks + " блоков длины 128 байт со сменой ключа каждые " + keyChangeFrequency +
                " блоков затрачено: " + (System.currentTimeMillis() - start) + " мс");
    }

    public static void main(String[] args) {
        speedTestForArbitraryOfSigningFiles(new File("C:\\Users\\fvd\\Desktop\\100MB.txt"));
        speedTestForArbitraryBlocksOfSigningMessageWithChangingKey(1000, 10);
        speedTestForArbitraryBlocksOfSigningMessage(1000);
    }
}
