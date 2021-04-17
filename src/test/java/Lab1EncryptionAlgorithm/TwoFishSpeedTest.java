package Lab1EncryptionAlgorithm;

import Lab4EncryptionModes.EncryptionAlgorithmWithMode;

import java.io.File;
import java.util.Arrays;

public class TwoFishSpeedTest {
    public static void speedTestForArbitraryBlocksOfPlainText(TwoFish twoFish) {
        byte[] blockOfPlainData = new byte[16];
        Arrays.fill(blockOfPlainData, (byte) 0xFF);
        long oneBlockTime = 0;
        long thousandBlocksTime = 0;
        long millionBlocksTime = 0;
        long start = System.currentTimeMillis();
        long startInNano = System.nanoTime();
        for (int i = 0; i < 1000000; i++) {
            twoFish.encryptOneBlock(blockOfPlainData);
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

    public static void speedTestForArbitraryFiles(EncryptionAlgorithmWithMode twoFish) {
        File oneMbFile = new File("C:\\Users\\fvd\\Desktop\\1MB.txt");
        File hundredMbFile = new File("C:\\Users\\fvd\\Desktop\\100MB.txt");
        File thousandMbFile = new File("C:\\Users\\fvd\\Desktop\\1000MB.txt");
        File oneMbFileEncrypted = new File("C:\\Users\\fvd\\Desktop\\1MB.txt.encrypted");
        File hundredMbFileEncrypted = new File("C:\\Users\\fvd\\Desktop\\100MB.txt.encrypted");
        File thousandMbFileEncrypted = new File("C:\\Users\\fvd\\Desktop\\1000MB.txt.encrypted");
        String pathForResultFiles = "C:\\Users\\fvd\\Desktop";
        long end;
        long start = System.currentTimeMillis();
        twoFish.encryptFile(oneMbFile, pathForResultFiles);
        end = System.currentTimeMillis();
        System.out.println("На шифрование файла размером 1 Мб затрачено: " + (end - start) + " мс");
        start = System.currentTimeMillis();
        twoFish.decryptFile(oneMbFileEncrypted, pathForResultFiles);
        end = System.currentTimeMillis();
        System.out.println("На расшифровку файла размером 1 Мб затрачено: " + (end - start) + " мс");
        System.out.println("============================================");
        start = System.currentTimeMillis();
        twoFish.encryptFile(hundredMbFile, pathForResultFiles);
        end = System.currentTimeMillis();
        System.out.println("На шифрование файла размером 100 Мб затрачено: " + (end - start) + " мс");
        start = System.currentTimeMillis();
        twoFish.decryptFile(hundredMbFileEncrypted, pathForResultFiles);
        end = System.currentTimeMillis();
        System.out.println("На расшифровку файла размером 100 Мб затрачено: " + (end - start) + " мс");
        System.out.println("============================================");
        start = System.currentTimeMillis();
        twoFish.encryptFile(thousandMbFile, pathForResultFiles);
        end = System.currentTimeMillis();
        System.out.println("На шифрование файла размером 1000 Мб затрачено: " + (end - start) + " мс");
        start = System.currentTimeMillis();
        twoFish.decryptFile(thousandMbFileEncrypted, pathForResultFiles);
        end = System.currentTimeMillis();
        System.out.println("На расшифровку файла размером 1000 Мб затрачено: " + (end - start) + " мс");
    }

 /*   public static void speedTestForArbitraryBlocksOfPlainTextWithChangingKey(TwoFish twoFish, int k) {
        long[] startKey = twoFish.getKey();
        long[] ffKey = new long[k];
        byte[] data = new byte[16];
        Arrays.fill(ffKey, 0xFFFFFFFFFFFFFFFFL);
        boolean keyFlag = false;
        long start = System.currentTimeMillis();
        for (int i = 1; i <= 1000000; i++) {
            if (i % 10 == 0 && !keyFlag) {
                twoFish.setKey(ffKey);
                keyFlag = true;
            } else if (i % 10 == 0) {
                twoFish.setKey(startKey);
                keyFlag = false;
            }
            twoFish.encryptMessage(data);
        }
        System.out.println("На шифрование 1000000 блоков открытого текста со сменой ключа каждые 10 блоков затрачено: " +
                (System.currentTimeMillis() - start) + " мс");
        start = System.currentTimeMillis();
        for (int i = 1; i <= 1000000; i++) {
            if (i % 10 == 0 && !keyFlag) {
                twoFish.setKey(ffKey);
                keyFlag = true;
            } else if (i % 10 == 0) {
                twoFish.setKey(startKey);
                keyFlag = false;
            }
            twoFish.decryptMessage(data);
        }
        System.out.println("На расшифровку 1000000 блоков открытого текста со сменой ключа каждые 10 блоков затрачено: " +
                (System.currentTimeMillis() - start) + " мс");
        System.out.println("============================================");
        start = System.currentTimeMillis();
        for (int i = 1; i <= 1000000; i++) {
            if (i % 100 == 0 && !keyFlag) {
                twoFish.setKey(ffKey);
                keyFlag = true;
            } else if (i % 100 == 0 && keyFlag) {
                twoFish.setKey(startKey);
                keyFlag = false;
            }
            twoFish.encryptMessage(data);
        }
        System.out.println("На шифрование 1000000 блоков открытого текста со сменой ключа каждые 100 блоков затрачено: " +
                (System.currentTimeMillis() - start) + " мс");
        start = System.currentTimeMillis();
        for (int i = 1; i <= 1000000; i++) {
            if (i % 100 == 0 && !keyFlag) {
                twoFish.setKey(ffKey);
                keyFlag = true;
            } else if (i % 100 == 0 && keyFlag) {
                twoFish.setKey(startKey);
                keyFlag = false;
            }
            twoFish.decryptMessage(data);
        }
        System.out.println("На расшифровку 1000000 блоков открытого текста со сменой ключа каждые 100 блоков затрачено: " +
                (System.currentTimeMillis() - start) + " мс");
        System.out.println("============================================");
        start = System.currentTimeMillis();
        for (int i = 1; i <= 1000000; i++) {
            if (i % 1000 == 0 && !keyFlag) {
                twoFish.setKey(ffKey);
                keyFlag = true;
            } else if (i % 1000 == 0 && keyFlag) {
                twoFish.setKey(startKey);
                keyFlag = false;
            }
            twoFish.encryptMessage(data);
        }
        System.out.println("На шифрование 1000000 блоков открытого текста со сменой ключа каждые 1000 блоков затрачено: " +
                (System.currentTimeMillis() - start) + " мс");
        start = System.currentTimeMillis();
        for (int i = 1; i <= 1000000; i++) {
            if (i % 1000 == 0 && !keyFlag) {
                twoFish.setKey(ffKey);
                keyFlag = true;
            } else if (i % 1000 == 0 && keyFlag) {
                twoFish.setKey(startKey);
                keyFlag = false;
            }
            twoFish.decryptMessage(data);
        }
        System.out.println("На расшифровку 1000000 блоков открытого текста со сменой ключа каждые 1000 блоков затрачено: " +
                (System.currentTimeMillis() - start) + " мс");
    }*/

}
