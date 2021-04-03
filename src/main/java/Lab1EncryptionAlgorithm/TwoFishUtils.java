package Lab1EncryptionAlgorithm;

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
     * Умножение матрицы многочленов на вектор многочленов
     *
     * @param matrix    матрица многочленов
     * @param vector    вектор многочленов
     * @param primitive примитивный многочлен степени 9
     * @return возвращает число полученное из вектора после умножения
     * @author Ilya Ryzhov
     */
    public static int multiplyMatrixByVectorModPrimitiveWithIntResult(char[] vector, char[][] matrix, char primitive) {
        char[] resultVector = multiplyMatrixByVectorModPrimitive(vector, matrix, primitive);
        int result = 0;
        for (int i = 0; i < resultVector.length; i++) {
            result += (resultVector[i] & 0xFF) * (1 << (8 * i));
        }
        return result;
    }

    public static char[] multiplyMatrixByVectorModPrimitive(char[] vector, char[][] matrix, char primitive) {
        char[] resultVector = new char[matrix.length];
        for (int i = 0; i < matrix.length; i++) {
            for (int j = 0; j < matrix[0].length; j++) {
                resultVector[i] ^= multiplyPolynomialsModPrimitive(matrix[i][j], (char) (vector[j] & 0xFF), primitive);
            }
        }
        return resultVector;
    }

    private static char multiplyPolynomialsModPrimitive(char a, char b, char primitive) {
        int result = 0;
        for (int i = 0; i < 8; i++) {
            int lastBit = b & 1;
            if (lastBit != 0) {
                int addendum = a;
                for (int j = 0; j < i; j++) {
                    addendum = modPrimitive((char) (addendum << 1), primitive);
                }
                result ^= addendum;
            }
            b >>>= 1;
        }
        return (char) result;
    }

    private static char modPrimitive(char a, char primitive) {
        return (a & 0b100000000) != 0 ? (char) (a ^ primitive) : a;
    }

    /**
     * Представление массива элементов типа long в виде массива элемента типов char(для разбиения ключа на 8-битные значения)
     *
     * @param longs массив long-ов
     * @return массив char-ов содержащий в себе элементы от 0 до 255
     * @author Ilya Ryzhov
     */
    public static char[] splitLongArrayToByteArray(long[] longs) {
        char[] vectorOfBytes = new char[8 * longs.length];
        for (int i = 0; i < longs.length; i++) {
            long partOfKey = longs[i];
            for (int j = 7; j >= 0; j--) {
                vectorOfBytes[j + 8 * i] = (char) ((partOfKey & 0xFF));
                partOfKey >>>= 8;
            }
        }
        return vectorOfBytes;
    }

    /**
     * Преобразование массива char-ов в массив long-ов (для формирования ключа)
     *
     * @param chars массив из элементов 0..255, которые надо преобразовать в массив long
     * @return массив long, соответствующий массиву chars
     * @author Ilya Ryzhov
     */
    public static long[] convertCharArrayToLongArray(char[] chars) {
        long[] result = new long[chars.length / 8];
        for (int i = 0; i < result.length; i++) {
            long element = 0;
            for (int j = 0; j < 8; j++) {
                element ^= chars[8 * i + j];
                if (j != 7)
                    element <<= 8;
            }
            result[i] = element;
        }
        return result;
    }

    /**
     * Преобразование массива char-ов в массив int-ов (для формирования ключа)
     *
     * @param chars массив из элементов 0..255, которые надо преобразовать в массив int
     * @return массив int-ов, соответствующий массиву chars, байты в элементах выходноо массива располагаются в порядке little-endian
     * @author Ilya Ryzhov
     */
    public static int[] convertCharArrayToIntArray(char[] chars) {
        int[] ints = new int[4];
        for (int i = 0; i < ints.length; i++) {
            for (int j = 0; j < 4; j++) {
                ints[i] += chars[4 * i + j] * (1 << (8 * j));
            }
        }
        return ints;
    }
}
