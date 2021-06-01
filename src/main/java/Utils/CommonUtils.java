package Utils;

import java.io.File;
import java.util.Arrays;

public class CommonUtils {

    /**
     * Представление массива элементов типа long в виде массива элементов типа byte
     *
     * @param longs массив long-ов
     * @return массив байтов
     * @author Ilya Ryzhov
     */
    public static byte[] convertLongArrayToByteArray(long[] longs) {
        byte[] vectorOfBytes = new byte[8 * longs.length];
        for (int i = 0; i < longs.length; i++) {
            long partOfKey = longs[i];
            for (int j = 7; j >= 0; j--) {
                vectorOfBytes[j + 8 * i] = (byte) (partOfKey);
                partOfKey >>>= 8;
            }
        }
        return vectorOfBytes;
    }

    /**
     * Представление массива элементов типа int в виде массива элементов типа byte
     *
     * @param ints массив int-ов
     * @return массив байтов
     * @author Ilya Ryzhov
     */
    public static byte[] convertIntArrayToByteArray(int[] ints) {
        byte[] vectorOfBytes = new byte[4 * ints.length];
        for (int i = 0; i < ints.length; i++) {
            int word = ints[i];
            for (int j = 3; j >= 0; j--) {
                vectorOfBytes[j + 4 * i] = (byte) (word);
                word >>>= 8;
            }
        }
        return vectorOfBytes;
    }

    /**
     * Преобразование массива байтов в массив long-ов
     *
     * @param bytes массив байтов, которые надо преобразовать в массив long
     * @return массив long, соответствующий массиву bytes
     * @author Ilya Ryzhov
     */
    public static long[] convertByteArrayToLongArray(byte[] bytes) {
        long[] result = new long[bytes.length / 8];
        for (int i = 0; i < result.length; i++) {
            long element = 0;
            for (int j = 0; j < 8; j++) {
                element ^= (bytes[8 * i + j] & 0xFF);
                if (j != 7)
                    element <<= 8;
            }
            result[i] = element;
        }
        return result;
    }

    /**
     * Преобразование массива байтов в массив int-ов
     *
     * @param bytes массив байтов, которые надо преобразовать в массив int
     * @return массив int-ов, соответствующий массиву bytes, байты в элементах выходного массива располагаются в порядке little-endian
     * @author Ilya Ryzhov
     */
    public static int[] convertByteArrayToIntArrayLittleEndian(byte[] bytes) {
        int[] ints = new int[bytes.length / 4];
        for (int i = 0; i < ints.length; i++) {
            int offset = i * 4;
            ints[i] = (bytes[offset + 3] & 0xFF) << 24 ^ (bytes[offset + 2] & 0xFF) << 16 ^ (bytes[offset + 1] & 0xFF) << 8 ^ (bytes[offset] & 0xFF);
        }
        return ints;
    }

    /**
     * Преобразование массива байтов в массив long-ов
     *
     * @param bytes массив байтов, которые надо преобразовать в массив long
     * @return массив long-ов, соответствующий массиву bytes, байты в элементах выходного массива располагаются в порядке little-endian
     * @author Ilya Ryzhov
     */
    public static long[] convertByteArrayToLongArrayLittleEndian(byte[] bytes) {
        long[] ints = new long[bytes.length / 8];
        for (int i = 0; i < ints.length; i++) {
            int offset = i * 8;
            ints[i] = (bytes[offset + 7] & 0xFFL) << 56 ^ (bytes[offset + 6] & 0xFFL) << 48 ^ (bytes[offset + 5] & 0xFFL) << 40 ^ (bytes[offset + 4] & 0xFFL) << 32
                    ^ (bytes[offset + 3] & 0xFFL) << 24 ^ (bytes[offset + 2] & 0xFFL) << 16 ^ (bytes[offset + 1] & 0xFFL) << 8 ^ (bytes[offset] & 0xFFL);
        }
        return ints;
    }

    /**
     * Преобразование массива байтов в целое число типа int
     *
     * @param bytes массив байтов
     * @return целое число типа int , составленное из массива bytes, байты в числе идут в том же порядке, что и в массиве
     * @author Ilya Ryzhov
     */
    public static int convertByteArrayToInt(byte[] bytes) {
        return (bytes[0] & 0xFF) << 24 ^ (bytes[1] & 0xFF) << 16 ^ (bytes[2] & 0xFF) << 8 ^ (bytes[3] & 0xFF);
    }

    /**
     * Преобразование массива байтов в целое число типа long
     *
     * @param bytes массив байтов
     * @return целое число типа long, составленное из массива bytes, байты в числе идут в том же порядке, что и в массиве
     * @author Ilya Ryzhov
     */
    public static long convertByteArrayToLong(byte[] bytes) {
        return (bytes[0] & 0xFFL) << 56 ^ (bytes[1] & 0xFFL) << 48 ^ (bytes[2] & 0xFFL) << 40 ^ (bytes[3] & 0xFFL) << 32
                ^ (bytes[4] & 0xFFL) << 24 ^ (bytes[5] & 0xFFL) << 16 ^ (bytes[6] & 0xFFL) << 8 ^ (bytes[7] & 0xFFL);
    }

    /**
     * Создает абсолютное имя зашифрованного файла
     *
     * @param fileToEncrypt        файл, который нужно зашифровать
     * @param pathForEncryptedFile путь, где должен лежать зашифрованный файл
     * @return конкатенация pathForDecryptedFile, разделителя пути к файлу, имени файла и постфикса .encrypted
     * @author Ilya Ryzhov
     */
    public static String getAbsoluteEncryptedFileName(File fileToEncrypt, String pathForEncryptedFile) {
        return pathForEncryptedFile + File.separator + fileToEncrypt.getName() + ".encrypted";
    }


    /**
     * Создает абсолютное имя расшифрованного файла
     *
     * @param fileToDecrypt        файл, который нужно расшифровать
     * @param pathForDecryptedFile путь, где должен лежать расшифрованный файл
     * @return конкатенация pathForDecryptedFile, разделителя пути к файлу, префикса decrypted_
     * и исходного имени файла до шифрования(без постфикса .encrypted)
     * @author Ilya Ryzhov
     */
    public static String getAbsoluteDecryptedFileName(File fileToDecrypt, String pathForDecryptedFile) {
        String nameOfFileToDecrypt = fileToDecrypt.getName();
        return pathForDecryptedFile + File.separator + "decrypted_" + nameOfFileToDecrypt.substring(0, nameOfFileToDecrypt.indexOf(".encrypted"));
    }

    /**
     * Выводит массив байтов в 16-ричном представлении
     *
     * @param array выводимый массив
     * @author Ilya Ryzhov
     */
    public static void printByteArrayHexFormat(byte[] array) {
        for (byte b : array) {
            System.out.print(Integer.toHexString(b & 0xff));
        }
        System.out.println();
    }

    /**
     * Склеивает два массива байтов
     *
     * @param firstArray  первый массив
     * @param secondArray второй массив
     * @return объединенный массив, в котором сначала идут элементы firstArray, затем элементы secondArray
     * @author Ilya Ryzhov
     */
    public static byte[] concatenateByteArrays(byte[] firstArray, byte[] secondArray) {
        byte[] resultArray = Arrays.copyOf(firstArray, firstArray.length + secondArray.length);
        System.arraycopy(secondArray, 0, resultArray, firstArray.length, secondArray.length);
        return resultArray;
    }
}
