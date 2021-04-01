package Lab1EncryptionAlgorithm;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

public class TwoFish {
    private final int k;
    private int[] wordsOfExpandedKey;//fin
    private final long[] key;
    private final char MDS_PRIMITIVE = 0b101101001;
    private final char RS_PRIMITIVE = 0b101001101;
    private final TwoFishUtils twoFishUtils;
    private final int[] evenMMembers;
    private final int[] oddMMembers;
    private final int[] sVector;
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
        twoFishUtils = new TwoFishUtils(k);
        evenMMembers = new int[k];
        oddMMembers = new int[k];
        sVector = new int[k];
        wordsOfExpandedKey = new int[40];
        initializeKeyBasis();
        initializeExpandedKeyWords();
    }

    public byte[] cipherOneBlock(byte[] plainText) {
        int[] plainTextWords = new int[4];
        for (int i = 0; i < plainTextWords.length; i++) {
            for (int j = 0; j < 4; j++) {
                plainTextWords[i] = plainText[4 * i + j] * (int) Math.pow(2, 8 * j);
            }
        }
        int[] rZero = new int[4];
        for (int i = 0; i < rZero.length; i++) {
            rZero[i] = plainTextWords[i] ^ wordsOfExpandedKey[i];
        }
        int[] roundR = new int[4];
        System.arraycopy(rZero, 0, roundR, 0, rZero.length);
        int[] roundPlusOneR = new int[4];
        for (int r = 0; r < 16; r++) {
            int[] fFunctionResult = fFnunction(roundR[0], roundR[1], r);
            roundPlusOneR[0] = Integer.rotateRight(roundR[2] ^ fFunctionResult[0], 1);
            roundPlusOneR[1] = Integer.rotateLeft(roundR[3], 1) ^ fFunctionResult[1];
            roundPlusOneR[2] = roundR[0];
            roundPlusOneR[3] = roundR[1];
            System.arraycopy(roundPlusOneR, 0, roundR, 0, roundPlusOneR.length);
        }
        int[] cipherWords = new int[4];
        for (int i = 0; i < cipherWords.length; i++) {
            cipherWords[i] = roundPlusOneR[(i + 2) % 4] ^ wordsOfExpandedKey[i + 4];
        }
        byte[] cipherBytes = new byte[16];
        for (int i = 0; i < cipherBytes.length; i++) {
            cipherBytes[i] = (byte) (cipherWords[i / 4] / (int) Math.pow(2, 8 * (i % 4)));
        }
        return cipherBytes;
    }

    //скорее всего
    int[] fFnunction(int rZero, int rOne, int roundNumber) {
        int tZero = gFunction(rZero);
        int tOne = gFunction(Integer.rotateLeft(rOne, 8));
        int fZero = tZero + tOne + wordsOfExpandedKey[2 * roundNumber + 8];
        int fOne = tZero + 2 * tOne + wordsOfExpandedKey[2 * roundNumber + 9];
        return new int[]{fZero, fOne};
    }

    //Скорее всего работает
    //TODO понять описание функции в алгоритме
    int gFunction(int x) {
        int[] inputForHFunction = new int[k + 1];
        inputForHFunction[0] = x;
        System.arraycopy(sVector, 0, inputForHFunction, 1, sVector.length);
        return hFunction(inputForHFunction);
    }


    /**
     * Разбивает блок из 128 бит на 4 блока по 32 бита
     *
     * @param leftPart  - левые 64 бита  128 бит
     * @param rightPart - правые 64 бита 128 бит
     * @return массив 32-битных слов, образующих 128 бит
     * @author Ilya Ryzhov
     **//*
    int[] separateBits(long leftPart, long rightPart) {//Разбивает блок из 128 бит на 4 блока по 32 бита
        int[] result = new int[4];
        result[0] = (int) (leftPart >>> 32);
        result[1] = (int) leftPart;
        result[2] = (int) (rightPart >>> 32);
        result[3] = (int) rightPart;
        return result;
    }*/

    //Работает
    private void initializeKeyBasis() {
        int[] vectorM = generateMKeys(key);
        for (int i = 0; i < vectorM.length; i++) {
            if (i % 2 == 0)
                evenMMembers[i / 2] = vectorM[i];
            else oddMMembers[i / 2] = vectorM[i];
        }
        byte[] mKeys = twoFishUtils.splitLongArrayToByteArray(key);
        for (int i = 0; i < k; i++) {
            byte[] mVector = new byte[8];
            System.arraycopy(mKeys, 8 * i, mVector, 0, 8);
            sVector[i] = twoFishUtils.multiplyMatrixByVectorModPrimitive(mVector, RS, RS_PRIMITIVE);
        }
    }

    //Работает------
    private void initializeExpandedKeyWords() {
        int p = (int) Math.pow(2, 24) + (int) Math.pow(2, 16) + (int) Math.pow(2, 8) + 1;
        for (int i = 0; i < 20; i++) {
            int[] hInputForA = new int[evenMMembers.length + 1];
            hInputForA[0] = 2 * i * p;
            System.arraycopy(evenMMembers, 0, hInputForA, 1, evenMMembers.length);
            int[] hInputForB = new int[oddMMembers.length + 1];
            hInputForB[0] = (2 * i + 1) * p;
            System.arraycopy(oddMMembers, 0, hInputForB, 1, oddMMembers.length);
            int A = hFunction(hInputForA);
            int B = Integer.rotateLeft(hFunction(hInputForB), 8);
            wordsOfExpandedKey[2 * i] = A + B;
            wordsOfExpandedKey[2 * i + 1] = Integer.rotateLeft(A + 2 * B, 9);
        }
    }

    private int[] generateMKeys(long[] key) {//Генерирует 2*k 32-битных слова Mi из ключа M
        byte[] mKeys = twoFishUtils.splitLongArrayToByteArray(key);
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


    //TODO проверить код, проверить сдвиги во всей проге, особенно эту функцию, дописать начатые функции
    int hFunction(int[] words) {
        int x = words[0];
        byte[] bytesOfX = new byte[4];
        for (int i = 0; i < 4; i++) {
            //bytesOfX[i] = (byte) (x / (int) Math.pow(2, 8 * i));
            bytesOfX[i] = (byte) (x & 0xFF);
            x >>>= 8;
        }
        byte[][] bytesOfL = new byte[k][4];
        for (int i = 0; i < k; i++) {//TODO Разобраться с индексами
            int word = words[i + 1];//???
            for (int j = 0; j < 4; j++) {
                //  bytesOfL[i][j] = (byte) (word / (int) Math.pow(2, 8 * j));
                //word <<= 8;
                bytesOfL[i][j] = (byte) (word & 0xFF);
                word >>>= 8;
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
        return twoFishUtils.multiplyMatrixByVectorModPrimitive(y[0], MDS, MDS_PRIMITIVE);
    }

    public void setWordsOfExpandedKey(int[] wordsOfExpandedKey) {
        this.wordsOfExpandedKey = wordsOfExpandedKey;
    }

    byte qSubstitution(byte x, byte[][] qTable) {//применяет q подстановку к x с использованием матрицы qTable
        int unsignedX = Byte.toUnsignedInt(x);
        int a0 = unsignedX / 16;
        int b0 = unsignedX % 16;
        int a1 = a0 ^ b0;
        int b1 = (a0 ^ twoFishUtils.ROR4(b0) ^ (8 * a0)) % 16;
        int a2 = qTable[0][a1];
        int b2 = qTable[1][b1];
        int a3 = a2 ^ b2;
        int b3 = (a2 ^ twoFishUtils.ROR4(b2) ^ (8 * a2)) % 16;
        int a4 = qTable[2][a3];
        int b4 = qTable[3][b3];
        return (byte) (16 * b4 + a4);
    }


    public static void main(String[] args) {
        //TwoFish twoFish2 = new TwoFish(new long[]{0, 0});
        TwoFish twoFish2 = new TwoFish(new long[]{0x9F589F5CF6122C32L, 0xB6BFEC2F2AE8C35AL});
        //PT=D491DB16E7B1C39E86CB086B789F5419
        byte[] cipherBytes = twoFish2.cipherOneBlock(new byte[] {
            0xd4, 0x91, 0xdb, 0x16, 0xe7, 0xb1, 0xc3, 0x9e, 0x86, 0xcb, 0x08, 0x6b, 0x78, 0x9f, 0x54, 0x19,});

        StringBuilder string2 = new StringBuilder();
        for (int i = 0; i < cipherBytes.length; i++) {
            string2.append(Integer.toHexString(Byte.toUnsignedInt(cipherBytes[i])));
        }
        System.out.println(string2.toString().toUpperCase().equals("9F589F5CF6122C32B6BFEC2F2AE8C35A")); //rabotaet
        //   TwoFish twoFish4 = new TwoFish(new long[]{0x0123456789ABCDEFL, 0xFEDCBA9876543210L, 0x0011223344556677L, 0x8899AABBCCDDEEFFL});
      /*  int[] goodKeys = new int[]{
                0x5EC769BF, 0x44D13C60,
                0x76CD39B1, 0x16750474,
                0x349C294B, 0xEC21F6D6,
                0x4FBD10B4, 0x578DA0ED,
                0xC3479695, 0x9B6958FB,
                0x6A7FBC4E, 0x0BF1830B,
                0x61B5E0FB, 0xD78D9730,
                0x7C6CF0C4, 0x2F9109C8,
                0xE69EA8D1, 0xED99BDFF,
                0x35DC0BBD, 0xA03E5018,
                0xFB18EA0B, 0x38BD43D3,
                0x76191781, 0x37A9A0D3,
                0x72427BEA, 0x911CC0B8,
                0xF1689449, 0x71009CA9,
                0xB6363E89, 0x494D9855,
                0x590BBC63, 0xF95A28B5,
                0xFB72B4E1, 0x2A43505C,
                0xBFD34176, 0x5C133D12,
                0x3A9247F7, 0x9A3331DD,
                0xEE7515E6, 0xF0D54DCD};
        twoFish4.setWordsOfExpandedKey(goodKeys);*/
        //byte[] cipherBytes = twoFish4.cipherOneBlock(new byte[16]);
        StringBuilder string4 = new StringBuilder();
        for (int i = 0; i < cipherBytes.length; i++) {
            string4.append(Integer.toHexString(Byte.toUnsignedInt(cipherBytes[i])));
        }
        System.out.println(string4);
    }
}


