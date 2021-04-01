package Lab1EncryptionAlgorithm;

public class TwoFishUtils {
    private final int k;

    public TwoFishUtils(int k) {
        this.k = k;
    }

    //Правильно
    public int ROR4(int a) {//Циклический правый сдвиг для 4-х битных значений
        int lastBit = a & 1;
        a >>>= 1;
        a ^= (lastBit << 3);
        return a;
    }

    //Скорее всего правильно
    public int multiplyMatrixByVectorModPrimitive(byte[] vector, char[][] matrix, char primitive) {
        byte[] resultVector = new byte[matrix.length];
        for (int i = 0; i < matrix.length; i++) {
            for (int j = 0; j < matrix[0].length; j++) {
                resultVector[i] ^= (byte) multiplyPolynomialsModPrimitive(matrix[i][j], (char) (vector[j] & 0xFF), primitive);
            }
        }
        int result = 0;
        for (int i = 0; i < resultVector.length; i++) {
            result += Byte.toUnsignedInt(resultVector[i]) * (int) Math.pow(2, 8 * i);
        }
        return result;
    }

    //вроде не используется
    private char multiplyPolynomialsModPrimitive(char a, char b, char primitive) {

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

    //вроде не используется
    private char modPrimitive(char a, char primitive) {
        return (a & 0b100000000) != 0 ? (char) (a ^ primitive) : a;
    }

    //Правильно
    public byte[] splitLongArrayToByteArray(long[] longs) {// разбиваем ключ M на mi
        byte[] vectorOfBytes = new byte[8 * k];
        for (int i = 0; i < k; i++) {
            long partOfKey = longs[i];
            for (int j = 0; j < 8; j++) {
                vectorOfBytes[j + 8 * i] = (byte) ((partOfKey & 0xFFFF000000000000L) >>> 56);
                partOfKey <<= 8;
            }
        }
        return vectorOfBytes;
    }

    public static void main(String[] args) {
        TwoFishUtils twoFishUtils = new TwoFishUtils(2);
        for (int i = 0; i < 16; i++) {
            System.out.println("i:" + Integer.toBinaryString(i) + " rotated" + Integer.toBinaryString(twoFishUtils.ROR4(i)));
        }
    }
}
