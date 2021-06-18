package encryptionModes;

import encryptionAlgorithm.EncryptionAlgorithm;
import encryptionAlgorithm.Twofish;

import java.io.File;

import static encryptionModes.EncryptionMode.*;

public class EncryptionModesSpeedTest {
    public static void speedTestForArbitraryBlocksOfPlainText(EncryptionAlgorithm encryptionAlgorithm) {
        byte[] thousandBlocksOfPlainData = new byte[16000];
        byte[] millionBlocksOfPlainData = new byte[16000000];
        Cipher[] ciphers = new Cipher[5];
        ciphers[0] = new Cipher(encryptionAlgorithm, ECB);
        ciphers[1] = new Cipher(encryptionAlgorithm, CBC, 2);
        ciphers[2] = new Cipher(encryptionAlgorithm, OFB, 2, 16);
        ciphers[3] = new Cipher(encryptionAlgorithm, CTR_ACPKM, 2, 16);
        ciphers[4] = new Cipher(encryptionAlgorithm, MGM, 16, 41);
        for (EncryptionMode mode : EncryptionMode.values()) {
            long thousandBlocksTime;
            long millionBlocksTime;
            long start = System.currentTimeMillis();
            ciphers[mode.ordinal()].encryptMessage(thousandBlocksOfPlainData);
            thousandBlocksTime = System.currentTimeMillis();
            System.out.println("На шифрование 1000 блоков в режиме " + mode + " затрачено: " + (thousandBlocksTime - start) + " мс");
            start = System.currentTimeMillis();
            ciphers[mode.ordinal()].encryptMessage(millionBlocksOfPlainData);
            millionBlocksTime = System.currentTimeMillis();
            System.out.println("На шифрование 1000000 блоков в режиме " + mode + " затрачено: " + (millionBlocksTime - start) + " мс");
        }
        EncryptionAlgorithmWithOMAC encryptionAlgorithmWithOMAC = new EncryptionAlgorithmWithOMAC(encryptionAlgorithm, 8);
        long thousandBlocksTime;
        long millionBlocksTime;
        long start = System.currentTimeMillis();
        encryptionAlgorithmWithOMAC.getImitationInsertFromMessage(thousandBlocksOfPlainData);
        thousandBlocksTime = System.currentTimeMillis();
        System.out.println("На получение имитовставки от 1000 блоков в режиме OMAC затрачено: " + (thousandBlocksTime - start) + " мс");
        start = System.currentTimeMillis();
        encryptionAlgorithmWithOMAC.getImitationInsertFromMessage(millionBlocksOfPlainData);
        millionBlocksTime = System.currentTimeMillis();
        System.out.println("На получение имитовставки от 1000000 блоков в режиме OMAC затрачено: " + (millionBlocksTime - start) + " мс");
    }

    public static void speedTestForArbitraryFiles(EncryptionAlgorithm encryptionAlgorithm) {
        File oneMbFile = new File("C:\\Users\\fvd\\Desktop\\1MB.txt");
        File hundredMbFile = new File("C:\\Users\\fvd\\Desktop\\100MB.txt");
        File thousandMbFile = new File("C:\\Users\\fvd\\Desktop\\1000MB.txt");
        String pathForResultFiles = "C:\\Users\\fvd\\Desktop";
        Cipher[] ciphers = new Cipher[5];
        ciphers[0] = new Cipher(encryptionAlgorithm, ECB);
        ciphers[1] = new Cipher(encryptionAlgorithm, CBC, 2);
        ciphers[2] = new Cipher(encryptionAlgorithm, OFB, 2, 16);
        ciphers[3] = new Cipher(encryptionAlgorithm, CTR_ACPKM, 2, 16);
        ciphers[4] = new Cipher(encryptionAlgorithm, MGM, 16, 41);
        for (EncryptionMode mode : EncryptionMode.values()) {
            long end;
            long start = System.currentTimeMillis();
            ciphers[mode.ordinal()].encryptFile(oneMbFile, pathForResultFiles);
            end = System.currentTimeMillis();
            System.out.println("На шифрование файла размером 1 Мб в режиме " + mode + " затрачено: " + (end - start) + " мс");
            start = System.currentTimeMillis();
            ciphers[mode.ordinal()].encryptFile(hundredMbFile, pathForResultFiles);
            end = System.currentTimeMillis();
            System.out.println("На шифрование файла размером 100 Мб в режиме " + mode + " затрачено: " + (end - start) + " мс");
            start = System.currentTimeMillis();
            ciphers[mode.ordinal()].encryptFile(thousandMbFile, pathForResultFiles);
            end = System.currentTimeMillis();
            System.out.println("На шифрование файла размером 1000 Мб в режиме " + mode + " затрачено: " + (end - start) + " мс");
            System.out.println("============================================");
        }
        EncryptionAlgorithmWithOMAC encryptionAlgorithmWithOMAC = new EncryptionAlgorithmWithOMAC(encryptionAlgorithm, 8);
        long start = System.currentTimeMillis();
        long end;
        encryptionAlgorithmWithOMAC.getImitationInsertFromFile(oneMbFile);
        end = System.currentTimeMillis();
        System.out.println("На получение имитовставки от файла размером 1 Мб в режиме OMAC затрачено: " + (end - start) + " мс");
        start = System.currentTimeMillis();
        encryptionAlgorithmWithOMAC.getImitationInsertFromFile(hundredMbFile);
        end = System.currentTimeMillis();
        System.out.println("На получение имитовставки от файла размером 100 Мб в режиме OMAC затрачено: " + (end - start) + " мс");
        start = System.currentTimeMillis();
        encryptionAlgorithmWithOMAC.getImitationInsertFromFile(thousandMbFile);
        end = System.currentTimeMillis();
        System.out.println("На получение имитовставки от файла размером 1000 Мб в режиме OMAC затрачено: " + (end - start) + " мс");
    }

        public static void speedTestForArbitraryBlocksOfPlainTextWithChangingKey(EncryptionAlgorithm encryptionAlgorithm, int k) {
        byte[] kBlocksOfPlainData = new byte[16 * k];
        Cipher[] ciphers = new Cipher[4];
        ciphers[0] = new Cipher(encryptionAlgorithm, ECB);
        ciphers[1] = new Cipher(encryptionAlgorithm, CBC, 2);
        ciphers[2] = new Cipher(encryptionAlgorithm, OFB, 2, 16);
        ciphers[3] = new Cipher(encryptionAlgorithm, MGM, 16, 41);
        for (Cipher cipher : ciphers) {
            long millionBlocksTime;
            long start = System.currentTimeMillis();
            for (int i = 0; i < 1000000 / k; i++) {
                cipher.encryptMessage(kBlocksOfPlainData);
                cipher.getEncryptionAlgorithmWithMode().setKey(new long[2]);
            }
            millionBlocksTime = System.currentTimeMillis();
            System.out.println("На шифрование 1000000 блоков в режиме " + cipher.getEncryptionMode() + " со сменой ключа каждые " + k + " блоков затрачено: "
                    + (millionBlocksTime - start) + " мс");
        }
        Cipher cipherWithCTRACPKM = new Cipher(encryptionAlgorithm, CTR_ACPKM, k, 16);
        long start = System.currentTimeMillis();
        cipherWithCTRACPKM.encryptMessage(new byte[16000000]);
        long millionBlocksTime = System.currentTimeMillis();
        System.out.println("На шифрование 1000000 блоков в режиме CTR_ACPKM со сменой ключа каждые " + k + " блоков затрачено: " + (millionBlocksTime - start) + " мс");
        EncryptionAlgorithmWithOMAC encryptionAlgorithmWithOMAC = new EncryptionAlgorithmWithOMAC(encryptionAlgorithm, 8);
        start = System.currentTimeMillis();
        for (int i = 0; i < 1000000 / k; i++) {
            encryptionAlgorithmWithOMAC.getImitationInsertFromMessage(kBlocksOfPlainData);
            encryptionAlgorithmWithOMAC.getEncryptionAlgorithm().setKey(new long[2]);
        }
        millionBlocksTime = System.currentTimeMillis();
        System.out.println("На получение имитовставки от 1000000 блоков в режиме OMAC со сменой ключа каждые " + k + " блоков затрачено: " + (millionBlocksTime - start) + " мс");
    }

    public static void main(String[] args) {
        Twofish twofish = new Twofish(new long[2]);
        speedTestForArbitraryBlocksOfPlainTextWithChangingKey(twofish, 10);
        speedTestForArbitraryBlocksOfPlainTextWithChangingKey(twofish, 100);
        speedTestForArbitraryBlocksOfPlainTextWithChangingKey(twofish, 1000);
    }
}
