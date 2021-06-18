package encryptionAlgorithm;

import encryptionModes.Cipher;

import java.io.File;
import java.util.Arrays;

import static encryptionModes.EncryptionMode.ECB;

public class TwofishSpeedTest {
    public static void speedTestForArbitraryBlocksOfPlainText(Twofish twofish) {
        byte[] blockOfPlainData = new byte[16];
        Arrays.fill(blockOfPlainData, (byte) 0xFF);
        long oneBlockTime = 0;
        long thousandBlocksTime = 0;
        long millionBlocksTime = 0;
        long start = System.currentTimeMillis();
        long startInNano = System.nanoTime();
        for (int i = 0; i < 1000000; i++) {
            twofish.encryptOneBlock(blockOfPlainData);
            if (i == 0)
                oneBlockTime = System.nanoTime();
            if (i == 999)
                thousandBlocksTime = System.currentTimeMillis();
            if (i == 999999)
                millionBlocksTime = System.currentTimeMillis();
        }
        System.out.println("На шифрование 1 блока затрачено: " + (oneBlockTime - startInNano) + " нс");
        System.out.println("На шифрование 1000 блоков затрачено: " + (thousandBlocksTime - start) + " мс");
        System.out.println("На шифрование 1000000 блоков затрачено: " + (millionBlocksTime - start) + " мс");
    }

    public static void speedTestForArbitraryFiles(Twofish twofish) {
        Cipher twofishWithECB = new Cipher(twofish, ECB);
        File oneMbFile = new File("C:\\Users\\fvd\\Desktop\\1MB.txt");
        File hundredMbFile = new File("C:\\Users\\fvd\\Desktop\\100MB.txt");
        File thousandMbFile = new File("C:\\Users\\fvd\\Desktop\\1000MB.txt");
        File oneMbFileEncrypted = new File("C:\\Users\\fvd\\Desktop\\1MB.txt.encrypted");
        File hundredMbFileEncrypted = new File("C:\\Users\\fvd\\Desktop\\100MB.txt.encrypted");
        File thousandMbFileEncrypted = new File("C:\\Users\\fvd\\Desktop\\1000MB.txt.encrypted");
        String pathForResultFiles = "C:\\Users\\fvd\\Desktop";
        long end;
        long start = System.currentTimeMillis();
        twofishWithECB.encryptFile(oneMbFile, pathForResultFiles);
        end = System.currentTimeMillis();
        System.out.println("На шифрование файла размером 1 Мб затрачено: " + (end - start) + " мс");
        start = System.currentTimeMillis();
        twofishWithECB.decryptFile(oneMbFileEncrypted, pathForResultFiles);
        end = System.currentTimeMillis();
        System.out.println("На расшифровку файла размером 1 Мб затрачено: " + (end - start) + " мс");
        System.out.println("============================================");
        start = System.currentTimeMillis();
        twofishWithECB.encryptFile(hundredMbFile, pathForResultFiles);
        end = System.currentTimeMillis();
        System.out.println("На шифрование файла размером 100 Мб затрачено: " + (end - start) + " мс");
        start = System.currentTimeMillis();
        twofishWithECB.decryptFile(hundredMbFileEncrypted, pathForResultFiles);
        end = System.currentTimeMillis();
        System.out.println("На расшифровку файла размером 100 Мб затрачено: " + (end - start) + " мс");
        System.out.println("============================================");
        start = System.currentTimeMillis();
        twofishWithECB.encryptFile(thousandMbFile, pathForResultFiles);
        end = System.currentTimeMillis();
        System.out.println("На шифрование файла размером 1000 Мб затрачено: " + (end - start) + " мс");
        start = System.currentTimeMillis();
        twofishWithECB.decryptFile(thousandMbFileEncrypted, pathForResultFiles);
        end = System.currentTimeMillis();
        System.out.println("На расшифровку файла размером 1000 Мб затрачено: " + (end - start) + " мс");
    }

    public static void speedTestForArbitraryBlocksOfPlainTextWithChangingKey(Twofish twofish, long[] startKey, int frequencyOfKeyChanging) {
        long[] ffKey = new long[startKey.length];
        byte[] data = new byte[16];
        Arrays.fill(ffKey, 0xFFFFFFFFFFFFFFFFL);
        boolean keyFlag = false;
        long start = System.currentTimeMillis();
        for (int i = 1; i <= 1000000; i++) {
            if (i % frequencyOfKeyChanging == 0 && !keyFlag) {
                twofish.setKey(ffKey);
                keyFlag = true;
            } else if (i % frequencyOfKeyChanging == 0) {
                twofish.setKey(startKey);
                keyFlag = false;
            }
            twofish.encryptOneBlock(data);
        }
        System.out.println("На шифрование 1000000 блоков открытого текста со сменой ключа каждые " + frequencyOfKeyChanging + " блоков затрачено: " +
                (System.currentTimeMillis() - start) + " мс");
        start = System.currentTimeMillis();
        for (int i = 1; i <= 1000000; i++) {
            if (i % frequencyOfKeyChanging == 0 && !keyFlag) {
                twofish.setKey(ffKey);
                keyFlag = true;
            } else if (i % frequencyOfKeyChanging == 0) {
                twofish.setKey(startKey);
                keyFlag = false;
            }
            twofish.decryptOneBlock(data);
        }
        System.out.println("На расшифровку 1000000 блоков открытого текста со сменой ключа каждые " + frequencyOfKeyChanging + " блоков затрачено: " +
                (System.currentTimeMillis() - start) + " мс");
    }
}
