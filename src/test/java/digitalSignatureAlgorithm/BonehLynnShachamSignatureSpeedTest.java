package digitalSignatureAlgorithm;

import hashAlgorithm.BlueMidnightWish;
import randomNumberGenerator.RandomNumberGenerator;

import java.io.*;

import static hashAlgorithm.BlueMidnightWishDigestSize.BLUE_MIDNIGHT_WISH_512;

public class BonehLynnShachamSignatureSpeedTest {
    public static void speedTestForArbitraryBlocksOfSigningMessage(int numberOfBlocks) {
        byte[] messageBlock = new byte[128];
        byte[] key = new RandomNumberGenerator().generateRandomBytes(23);
        BonehLynnShachamSignature bonehLynnShachamSignature = new BonehLynnShachamSignature(key, new BlueMidnightWish(BLUE_MIDNIGHT_WISH_512));
        byte[] signature;
        long start = System.currentTimeMillis();
        for (int i = 0; i < numberOfBlocks; i++) {
            signature = bonehLynnShachamSignature.getSignature(messageBlock);
            bonehLynnShachamSignature.verifySignature(messageBlock, signature,bonehLynnShachamSignature.getPublicKey());
        }
        System.out.println("На подпись и проверку подписи " + numberOfBlocks + " блоков длины 128 байт затрачено: " + (System.currentTimeMillis() - start) + " мс");
    }

    public static void speedTestForArbitrarySigningFiles(File file) {
        byte[] key = new RandomNumberGenerator().generateRandomBytes(23);
        BonehLynnShachamSignature bonehLynnShachamSignature = new BonehLynnShachamSignature(key, new BlueMidnightWish(BLUE_MIDNIGHT_WISH_512));
        long start = System.currentTimeMillis();
        byte[] signature = bonehLynnShachamSignature.getSignature(file);
        bonehLynnShachamSignature.verifySignature(file, signature,bonehLynnShachamSignature.getPublicKey());
        System.out.println("На подпись и проверку подписи файла размером " + file.length() + " байтов затрачено: " + (System.currentTimeMillis() - start) + " мс");
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
            bonehLynnShachamSignature.verifySignature(messageBlock, signature,bonehLynnShachamSignature.getPublicKey());
        }
        System.out.println("На подпись и проверку подписи " + numberOfBlocks + " блоков длины 128 байт со сменой ключа каждые " + keyChangeFrequency +
                " блоков затрачено: " + (System.currentTimeMillis() - start) + " мс");
    }

    public static void main(String[] args) {
        speedTestForArbitrarySigningFiles(new File("C:\\Users\\fvd\\Desktop\\1MB.txt"));
        speedTestForArbitrarySigningFiles(new File("C:\\Users\\fvd\\Desktop\\100MB.txt"));
        speedTestForArbitrarySigningFiles(new File("C:\\Users\\fvd\\Desktop\\1000MB.txt"));
        speedTestForArbitraryBlocksOfSigningMessage(1000);
        speedTestForArbitraryBlocksOfSigningMessageWithChangingKey(1000, 10);
    }
}
