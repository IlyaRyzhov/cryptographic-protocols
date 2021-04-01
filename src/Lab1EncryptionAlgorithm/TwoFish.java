package Lab1EncryptionAlgorithm;

import java.util.Arrays;

public class TwoFish {
    private final int k;
    private int[] wordsOfExpandedKey;
    private final long[] key;
    private final char MDS_PRIMITIVE = 0b101101001;
    private final char RS_PRIMITIVE = 0b101001101;
    private final byte[][] Q_ZERO = {
            {0x8, 0x1, 0x7, 0xD, 0x6, 0xF, 0x3, 0x2, 0x0, 0xB, 0x5, 0x9, 0xE, 0xC, 0xA, 0x4},
            {0xE, 0xC, 0xB, 0x8, 0x1, 0x2, 0x3, 0x5, 0xF, 0x4, 0xA, 0x6, 0x7, 0x0, 0x9, 0xD},
            {0xB, 0xA, 0x5, 0xE, 0x6, 0xD, 0x9, 0x0, 0xC, 0x8, 0xF, 0x3, 0x2, 0x4, 0x7, 0x1},
            {0xD, 0x7, 0xF, 0x4, 0x1, 0x2, 0x6, 0xE, 0x9, 0xB, 0x3, 0x0, 0x8, 0x5, 0xC, 0xA}
    };
    private final byte[][] Q_ONE = {
            {0x2, 0x8, 0xB, 0xD, 0xF, 0x7, 0x6, 0xE, 0x3, 0x1, 0x9, 0x4, 0x0, 0xA, 0xC, 0x5},
            {0x1, 0xE, 0x2, 0xB, 0x4, 0xC, 0x3, 0x7, 0x6, 0xD, 0xA, 0x5, 0xF, 0x9, 0x0, 0x8},
            {0x4, 0xC, 0x7, 0x5, 0x1, 0x6, 0x9, 0xA, 0x0, 0xE, 0xD, 0x8, 0x2, 0xB, 0x3, 0xF},
            {0xB, 0x9, 0x5, 0x1, 0xC, 0x3, 0xD, 0xE, 0x6, 0x4, 0x7, 0xF, 0x2, 0x0, 0x8, 0xA}
    };
    private final char[][] MDS = {
            {0x01, 0xEF, 0x5B, 0x5B},
            {0x5B, 0xEF, 0xEF, 0x01},
            {0xEF, 0x5B, 0x01, 0xEF},
            {0xEF, 0x01, 0xEF, 0x5B}
    };
    private final char[][] RS = {
            {0x01, 0xA4, 0x55, 0x87, 0x5A, 0x58, 0xDB, 0x9E},
            {0xA4, 0x56, 0x82, 0xF3, 0x1E, 0xC6, 0x68, 0xE5},
            {0x02, 0xA1, 0xFC, 0xC1, 0x47, 0xAE, 0x3D, 0x19},
            {0xA4, 0x55, 0x87, 0x5A, 0x58, 0xDB, 0x9E, 0x03}
    };

    public TwoFish(long[] key) {
        if (key.length == 1) {
            this.key = new long[]{key[0], 0L};
        } else this.key = key;
        k = key.length;
    }

    /**
     * Разбивает блок из 128 бит на 4 блока по 32 бита
     *
     * @param leftPart  - левые 64 бита  128 бит
     * @param rightPart - правые 64 бита 128 бит
     * @return массив 32-битных слов, образующих 128 бит
     * @author Ilya Ryzhov
     **/
    int[] separateBits(long leftPart, long rightPart) {//Разбивает блок из 128 бит на 4 блока по 32 бита
        int[] result = new int[4];
        result[0] = (int) (leftPart >>> 32);
        result[1] = (int) leftPart;
        result[2] = (int) (rightPart >>> 32);
        result[3] = (int) rightPart;
        return result;
    }

    int[] generateMKeys(long[] key) {//Генерирует 2*k 32-битных слова Mi из ключа M
        byte[] mKeys = splitLongArrayToByteArray(key);
        int[] MKeys = new int[2 * k];
        for (int i = 0; i < 2 * k; i++) {
            int Mi = 0;
            for (int j = 0; j < 4; j++) {
                int term = Byte.toUnsignedInt(mKeys[4 * i + j]) * (int) Math.pow(2, 8 * j);
                Mi += term;
            }
            MKeys[i] = Mi;
        }
        return MKeys;
    }

    byte[] splitLongArrayToByteArray(long[] longs) {// разбиваем ключ M на mi
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

    //TODO проверить код, проверить сдвиги во всей проге, особенно эту функцию, дописать начатые функции
    int hFunction(int[] words) {
        int x = words[0];
        byte[] bytesOfX = new byte[4];
        for (int i = 0; i < 4; i++) {
            bytesOfX[i] = (byte) (x >>> 24);
            x <<= 8;
        }
        byte[][] bytesOfL = new byte[k][4];
        for (int i = 0; i < k; i++) {
            int word = words[i];
            for (int j = 0; j < 4; j++) {
                bytesOfL[i][j] = (byte) (word >>> 24);
                word <<= 8;
            }
        }
        byte[][] y = new byte[k][4];
        System.arraycopy(bytesOfX, 0, y[k - 1], 0, 4);
        switch (k) {
            case 4: {
                y[2][0] = (byte) (qSubstitution(y[3][0], Q_ONE) ^ bytesOfL[3][0]);
                y[2][1] = (byte) (qSubstitution(y[3][1], Q_ZERO) ^ bytesOfL[3][1]);
                y[2][2] = (byte) (qSubstitution(y[3][2], Q_ZERO) ^ bytesOfL[3][2]);
                y[2][3] = (byte) (qSubstitution(y[3][3], Q_ONE) ^ bytesOfL[3][3]);
            }
            case 3: {
                y[1][0] = (byte) (qSubstitution(y[2][0], Q_ONE) ^ bytesOfL[2][0]);
                y[1][0] = (byte) (qSubstitution(y[2][1], Q_ONE) ^ bytesOfL[2][1]);
                y[1][0] = (byte) (qSubstitution(y[2][2], Q_ZERO) ^ bytesOfL[2][2]);
                y[1][0] = (byte) (qSubstitution(y[2][3], Q_ZERO) ^ bytesOfL[2][3]);
            }
            default: {
                y[0][0] = qSubstitution((byte) (qSubstitution((byte) (qSubstitution(y[1][0], Q_ZERO) ^ bytesOfL[1][0]), Q_ZERO) ^ bytesOfL[0][0]), Q_ONE);
                y[0][1] = qSubstitution((byte) (qSubstitution((byte) (qSubstitution(y[1][1], Q_ONE) ^ bytesOfL[1][1]), Q_ZERO) ^ bytesOfL[0][1]), Q_ZERO);
                y[0][2] = qSubstitution((byte) (qSubstitution((byte) (qSubstitution(y[1][2], Q_ZERO) ^ bytesOfL[1][2]), Q_ONE) ^ bytesOfL[0][2]), Q_ONE);
                y[0][3] = qSubstitution((byte) (qSubstitution((byte) (qSubstitution(y[1][3], Q_ONE) ^ bytesOfL[1][3]), Q_ONE) ^ bytesOfL[0][3]), Q_ZERO);
            }
        }
        return multiplyMatrixByVectorModPrimitive(y[0], MDS, MDS_PRIMITIVE);
    }

    /*   int multiplyMDSMatrixByYVector(byte[] yVector) {
           byte[] zVector = new byte[4];
           for (int i = 0; i < 4; i++)
               for (int j = 0; j < 4; j++) {
                   zVector[i] ^= (byte) multiplyPolynomialsModPrimitive(MDS[i][j], (char) (yVector[j] & 0xFF), MDS_PRIMITIVE);
               }
           int Z = 0;
           for (int i = 0; i < zVector.length; i++) {

               Z += Byte.toUnsignedInt(zVector[i]) * (int) Math.pow(2, 8 * i);
           }
           return Z;
       }

       int multiplyRSMatrixByMVector(byte[] yVector) {
           byte[] sVector = new byte[4];
           for (int i = 0; i < 4; i++)
               for (int j = 0; j < 8; j++) {
                   sVector[i] ^= (byte) multiplyPolynomialsModPrimitive(RS[i][j], (char) (yVector[j] & 0xFF), RS_PRIMITIVE);
               }
           int Z = 0;
           for (int i = 0; i < sVector.length; i++) {
               Z += Byte.toUnsignedInt(sVector[i]) * (int) Math.pow(2, 8 * i);
           }
           return Z;
       }*/
    int multiplyMatrixByVectorModPrimitive(byte[] vector, char[][] matrix, char primitive) {
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

    char multiplyPolynomialsModPrimitive(char a, char b, char primitive) {
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

    char modPrimitive(char a, char primitive) {
        return (a & 0b100000000) != 0 ? (char) (a ^ primitive) : a;
    }


    byte qSubstitution(byte x, byte[][] qTable) {//применяет q подстановку к x с использованием матрицы qTable
        int unsignedX = Byte.toUnsignedInt(x);
        int a0 = unsignedX / 16;
        int b0 = unsignedX % 16;
        int a1 = a0 ^ b0;
        int b1 = (a0 ^ ROR4(b0) ^ (8 * a0)) % 16;
        int a2 = qTable[0][a1];
        int b2 = qTable[1][b1];
        int a3 = a2 ^ b2;
        int b3 = (a2 ^ ROR4(b2) ^ (8 * a2)) % 16;
        int a4 = qTable[2][a3];
        int b4 = qTable[3][b3];
        return (byte) (16 * b4 + a4);
    }

    int ROR4(int a) {//Циклический правый сдвиг для 4-х битных значений
        int lastBit = a & 1;
        a >>>= 1;
        if (lastBit != 0)
            a ^= (lastBit << 3);
        return a;
    }

    public static void main(String[] args) {
        TwoFish twoFish = new TwoFish(new long[]{0, 0});
        byte[] y = {1, 0, 0, 0};
        System.out.println(Integer.toHexString(twoFish.multiplyMatrixByVectorModPrimitive(y, twoFish.MDS, twoFish.MDS_PRIMITIVE)));
        long[] key = {0x12FFFF1331231231L, 0x12FFFF18ABC1E800L};
        int[] mKeys = twoFish.generateMKeys(key);
        Arrays.stream(mKeys).forEach(m -> System.out.println(Integer.toHexString(m)));
        /*char a = 0b11111111;
        char b = 0b101;
        System.out.println(Integer.toBinaryString(twoFish.multiplyPolynomialsModPrimitive(a, b, twoFish.MDS_PRIMITIVE)));
        char MDSPrimitive = 0b10110101;
        char charA = (char) (((byte) 127) & 0xFF);
        System.out.println(Integer.toBinaryString((int) MDSPrimitive));
        System.out.println(Integer.toBinaryString(charA));
*/
/*
        long[] key = {0x12FFFF1331231231L, 0x12FFFF18ABC1E800L};
        StringBuilder key0 = new StringBuilder(Long.toBinaryString(key[0]));
        while (key0.length() != 64)
            key0.insert(0, "0");
        StringBuilder key1 = new StringBuilder(Long.toBinaryString(key[1]));
        while (key1.length() != 64)
            key1.insert(0, "0");
        System.out.println(key0.toString() + key1);
        String test1 = key0.toString() + key1;
        byte[] arr = splitLongArrayToByteArray(key);
        String test2 = "";
        for (int i = 0; i < arr.length; i++) {
            byte b = arr[i];
            StringBuilder binaryB = new StringBuilder(Integer.toBinaryString(Byte.toUnsignedInt(b)));
            while (binaryB.length() != 8)
                binaryB.insert(0, "0");
            System.out.print(binaryB);
            test2 += binaryB;
        }
        System.out.println();
        System.out.println(test1);
        System.out.println(test1.equals(test2));
        System.out.println("generated");
        System.out.println(test1.substring(0, 32));
        int[] mas = generateMKeys(key);
        for (int i = 0; i < mas.length; i++) {
            StringBuilder binary = new StringBuilder(Integer.toBinaryString(mas[i]));
            while (binary.length() != 32)
                binary.insert(0, "0");
            System.out.println(binary);
        }
        byte o = -1;
        System.out.println(Integer.toBinaryString(o));
        System.out.println((byte) (o >>> 4));
        System.out.println((byte) (o & 0xF));
        //      System.out.println(ROR4(5));*/
    }
}


