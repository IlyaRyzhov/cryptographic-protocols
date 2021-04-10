package Utils;

import java.io.File;

import static Utils.CommonUtils.convertByteArrayToInt;

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