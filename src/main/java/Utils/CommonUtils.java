package Utils;

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
     * @author ILya Ryzhov
     */
    public static int convertByteArrayToInt(byte[] bytes) {
        return (bytes[0] & 0xFF) << 24 ^ (bytes[1] & 0xFF) << 16 ^ (bytes[2] & 0xFF) << 8 ^ (bytes[3] & 0xFF);
    }

    /**
     * Преобразование массива байтов в целое число типа long
     *
     * @param bytes массив байтов
     * @return целое число типа long, составленное из массива bytes, байты в числе идут в том же порядке, что и в массиве
     * @author ILya Ryzhov
     */
    public static long convertByteArrayToLong(byte[] bytes) {
        return (bytes[0] & 0xFFL) << 56 ^ (bytes[1] & 0xFFL) << 48 ^ (bytes[2] & 0xFFL) << 40 ^ (bytes[3] & 0xFFL) << 32
                ^ (bytes[4] & 0xFFL) << 24 ^ (bytes[5] & 0xFFL) << 16 ^ (bytes[6] & 0xFFL) << 8 ^ (bytes[7] & 0xFFL);
    }

    public static void main(String[] args) {
        int[] mas = new int[]{0xff12345, 0xabcdef98};
        byte[] arr = convertIntArrayToByteArray(mas);
        for (int i = 0; i < arr.length; i++) {
            System.out.print(Integer.toHexString(arr[i] & 0xff) + " ");
        }
        System.out.println();
        System.out.println(Long.toHexString(convertByteArrayToLongArrayLittleEndian(new byte[]{0x12, 0x34, 0x55, 0x77, 0x12, 0x34, 0x55, 0x77})[0]));
    }
}
