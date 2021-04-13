package Lab2HashAlgorithm;

import Lab2HashAlgorithm.myImplementation.BlueMidnightWish;

import java.io.File;
import java.util.Arrays;

import static Lab2HashAlgorithm.myImplementation.BlueMidnightWishDigestSize.values;

public class BlueMidnightWishSpeedTest {
    public static void speedTestForArbitraryBlocksOfHashableMessage(BlueMidnightWish blueMidnightWish) {
        byte[] hashableMessage = new byte[blueMidnightWish.getBlockSize()];
        long startInNano = System.nanoTime();
        blueMidnightWish.computeHash(hashableMessage);
        System.out.println("На вычисление хеша 1 блока затрачено: " + (System.nanoTime() - startInNano) + " нс");
        hashableMessage = new byte[1000 * blueMidnightWish.getBlockSize()];
        long start = System.currentTimeMillis();
        blueMidnightWish.computeHash(hashableMessage);
        System.out.println("На вычисление хеша 1000 блоков затрачено: " + (System.currentTimeMillis() - start) + " мс");
        start = System.currentTimeMillis();
        hashableMessage = new byte[1000000 * blueMidnightWish.getBlockSize()];
        blueMidnightWish.computeHash(hashableMessage);
        System.out.println("На вычисление хеша 1000000 блоков затрачено: " + (System.currentTimeMillis() - start) + " мс");
    }

    public static void speedTestForArbitraryHashableFiles(BlueMidnightWish blueMidnightWish) {
        File oneMbFile = new File("C:\\Users\\fvd\\Desktop\\1MB.txt");
        File hundredMbFile = new File("C:\\Users\\fvd\\Desktop\\100MB.txt");
        File thousandMbFile = new File("C:\\Users\\fvd\\Desktop\\1000MB.txt");
        long start = System.currentTimeMillis();
        blueMidnightWish.computeHashOfFile(oneMbFile);
        System.out.println("На хеширование файла размером 1 Мб затрачено: " + (System.currentTimeMillis() - start) + " мс");
        start = System.currentTimeMillis();
        blueMidnightWish.computeHashOfFile(hundredMbFile);
        System.out.println("На хеширование файла размером 100 Мб затрачено: " + (System.currentTimeMillis() - start) + " мс");
        start = System.currentTimeMillis();
        blueMidnightWish.computeHashOfFile(thousandMbFile);
        System.out.println("На хеширование файла размером 1000 Мб затрачено: " + (System.currentTimeMillis() - start) + " мс");
    }

    public static void main(String[] args) {
        Arrays.stream(values()).forEach(blueMidnightWishDigestSize -> {
            BlueMidnightWish blueMidnightWish = new BlueMidnightWish(blueMidnightWishDigestSize);
            System.out.println("=====" + blueMidnightWishDigestSize.getAlgorithmName() + "=====");
            speedTestForArbitraryBlocksOfHashableMessage(blueMidnightWish);
         //   speedTestForArbitraryHashableFiles(blueMidnightWish);
        });
    }
}
