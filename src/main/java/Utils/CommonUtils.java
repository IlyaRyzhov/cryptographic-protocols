package Utils;

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
     * @return массив int-ов, соответствующий массиву bytes, байты в элементах выходноо массива располагаются в порядке little-endian
     * @author Ilya Ryzhov
     */
    public static int[] convertByteArrayToIntArrayLittleEndian(byte[] bytes) {
        int[] ints = new int[bytes.length / 4];
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

    public static void main(String[] args) {
        int[] mas = new int[]{0xff12345, 0xabcdef98};
        byte[] arr=convertIntArrayToByteArray(mas);
        for (int i = 0; i <arr.length ; i++) {
            System.out.print(Integer.toHexString(arr[i]&0xff)+" ");
        }
    }
}
