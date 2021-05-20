package Lab5RandomNumberGenerator;

import java.io.*;

public class RandomNumberGeneratorSpeedTest {
    public static void speedTestForRandomFile(int fileLength) {
        RandomNumberGenerator randomNumberGenerator = new RandomNumberGenerator();
        File file = new File("C:\\Users\\fvd\\Desktop\\random.txt");
        int remainder = fileLength;
        long start = System.currentTimeMillis();
        try (BufferedOutputStream bufferedOutputStream = new BufferedOutputStream(new FileOutputStream(file), 1048576)) {
            while (remainder != 0) {
                int numberBytesToWrite = Math.min(1048576, remainder);
                bufferedOutputStream.write(randomNumberGenerator.generateRandomBytes(numberBytesToWrite));
                remainder -= numberBytesToWrite;
            }
            System.out.println("На генерацию случайного файла размером " + fileLength + " байтов затрачено " + (System.currentTimeMillis() - start) / 1000 + "с");
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    public static void main(String[] args) {
        speedTestForRandomFile(1048576);
        speedTestForRandomFile(104857600);
    }
}
