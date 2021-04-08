package Lab1EncryptionAlgorithm;

import java.io.File;
import java.util.Arrays;

public class TwoFishUtils {

    /**
     * Циклический правый сдвиг для 4-х битных значений
     *
     * @param a 4-битное число
     * @return результат применения циклического сдвига вправо для числа a
     * @author Ilya Ryzhov
     */
    public static int ROR4(int a) {
        int lastBit = a & 1;
        a >>>= 1;
        a ^= (lastBit << 3);
        return a;
    }

    /**
     * Умножение матрицы многочленов на вектор многочленов с целочисленным результатом
     *
     * @param matrix    матрица многочленов
     * @param vector    вектор многочленов
     * @param primitive примитивный многочлен степени 9
     * @return возвращает число полученное из вектора после умножения
     * @author Ilya Ryzhov
     */
    public static int multiplyMatrixByVectorModPrimitiveWithIntResult(byte[] vector, byte[][] matrix, char primitive) {
        byte[] resultVector = multiplyMatrixByVectorModPrimitive(vector, matrix, primitive);
        return Integer.reverseBytes(convertByteArrayToInt(resultVector));
    }
    /**
     * Умножение матрицы многочленов на вектор многочленов с результатом в виде массива байтов.
     *
     * @param matrix    матрица многочленов
     * @param vector    вектор многочленов
     * @param primitive примитивный многочлен степени 9
     * @return возвращает массив byte полученный из вектора после умножения
     * @author Ilya Ryzhov
     */
    public static byte[] multiplyMatrixByVectorModPrimitive(byte[] vector, byte[][] matrix, char primitive) {
        byte[] resultVector = new byte[matrix.length];
        for (int i = 0; i < matrix.length; i++) {
            for (int j = 0; j < matrix[0].length; j++) {
                resultVector[i] ^= multiplyPolynomialsModPrimitive(matrix[i][j], vector[j], primitive);
            }
        }
        return resultVector;
    }

    private static byte multiplyPolynomialsModPrimitive(byte a, byte b, char primitive) {
        int result = 0;
        for (int i = 0; i < 8; i++) {
            int lastBit = b & 1;
            if (lastBit != 0) {
                int addendum = a & 0xFF;
                for (int j = 0; j < i; j++) {
                    addendum = modPrimitive((char) (addendum << 1), primitive);
                }
                result ^= addendum;
            }
            b >>>= 1;
        }
        return (byte) result;
    }

    private static char modPrimitive(char a, char primitive) {
        return (a & 0b100000000) != 0 ? (char) (a ^ primitive) : a;
    }

    /**
     * Представление массива элементов типа long в виде массива элементов типа byte(для разбиения ключа на 8-битные значения)
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
     * Преобразование массива байтов в массив long-ов (для формирования ключа)
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
     * Преобразование массива байтов в массив int-ов (для формирования ключа)
     *
     * @param bytes массив байтов, которые надо преобразовать в массив int
     * @return массив int-ов, соответствующий массиву bytes, байты в элементах выходноо массива располагаются в порядке little-endian
     * @author Ilya Ryzhov
     */
    public static int[] convertByteArrayToIntArray(byte[] bytes) {
        int[] ints = new int[4];
        for (int i = 0; i < ints.length; i++) {
            ints[i] = Integer.reverseBytes(convertByteArrayToInt(Arrays.copyOfRange(bytes, 4 * i, 4 * i + 4)));
        }
        return ints;
    }

    /**
     * Преобразование массива байтов в целое число
     *
     * @param bytes массив байтов
     * @return целое число, составленное из массива bytes, байты в числе идут в том же порядке, что и в массиве
     * @author ILya Ryzhov
     */
    public static int convertByteArrayToInt(byte[] bytes) {
        return (bytes[0] & 0xFF) << 24 ^ (bytes[1] & 0xFF) << 16 ^ (bytes[2] & 0xFF) << 8 ^ (bytes[3] & 0xFF);
    }

    /**
     * Создает абсолютное имя зашифрованного файла
     *
     * @param fileToEncrypt        файл, который нужно зашифровать
     * @param pathForEncryptedFile путь, где должен лежать зашифрованный файл
     * @return конкатенация pathForDecryptedFile, разделителя пути к файлу, имени файла и постфикса .encrypted
     * @author ILya Ryzhov
     */
    public static String createAbsoluteEncryptedFileName(File fileToEncrypt, String pathForEncryptedFile) {
        return pathForEncryptedFile + File.separator + fileToEncrypt.getName() + ".encrypted";
    }

    /**
     * Создает абсолютное имя расшифрованного файла
     *
     * @param fileToDecrypt        файл, который нужно расшифровать
     * @param pathForDecryptedFile путь, где должен лежать расшифрованный файл
     * @return конкатенация pathForDecryptedFile, разделителя пути к файлу, префикса decrypted_
     * и исходного имени файла до шифрования(без постфикса .encrypted)
     * @author ILya Ryzhov
     */
    public static String createAbsoluteDecryptedFileName(File fileToDecrypt, String pathForDecryptedFile) {
        String nameOfFileToDecrypt = fileToDecrypt.getName();
        return pathForDecryptedFile + File.separator + "decrypted_" + nameOfFileToDecrypt.substring(0, nameOfFileToDecrypt.indexOf(".encrypted"));
    }
}
