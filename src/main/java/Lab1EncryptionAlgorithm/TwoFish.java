package Lab1EncryptionAlgorithm;

public class TwoFish {
    private final int k;
    private final int[] wordsOfExpandedKey;
    private final long[] key;
    private static final char MDS_PRIMITIVE = 0b101101001;
    private static final char RS_PRIMITIVE = 0b101001101;
    private final TwoFishUtils twoFishUtils;
    private final int[] evenMMembers;
    private final int[] oddMMembers;
    private final int[] sVector;
    private static final byte[][] Q_ZERO = {
            {0x8, 0x1, 0x7, 0xD, 0x6, 0xF, 0x3, 0x2, 0x0, 0xB, 0x5, 0x9, 0xE, 0xC, 0xA, 0x4},
            {0xE, 0xC, 0xB, 0x8, 0x1, 0x2, 0x3, 0x5, 0xF, 0x4, 0xA, 0x6, 0x7, 0x0, 0x9, 0xD},
            {0xB, 0xA, 0x5, 0xE, 0x6, 0xD, 0x9, 0x0, 0xC, 0x8, 0xF, 0x3, 0x2, 0x4, 0x7, 0x1},
            {0xD, 0x7, 0xF, 0x4, 0x1, 0x2, 0x6, 0xE, 0x9, 0xB, 0x3, 0x0, 0x8, 0x5, 0xC, 0xA}
    };
    private static final byte[][] Q_ONE = {
            {0x2, 0x8, 0xB, 0xD, 0xF, 0x7, 0x6, 0xE, 0x3, 0x1, 0x9, 0x4, 0x0, 0xA, 0xC, 0x5},
            {0x1, 0xE, 0x2, 0xB, 0x4, 0xC, 0x3, 0x7, 0x6, 0xD, 0xA, 0x5, 0xF, 0x9, 0x0, 0x8},
            {0x4, 0xC, 0x7, 0x5, 0x1, 0x6, 0x9, 0xA, 0x0, 0xE, 0xD, 0x8, 0x2, 0xB, 0x3, 0xF},
            {0xB, 0x9, 0x5, 0x1, 0xC, 0x3, 0xD, 0xE, 0x6, 0x4, 0x7, 0xF, 0x2, 0x0, 0x8, 0xA}
    };
    private static final char[][] MDS = {
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

    public char[] cipherOneBlock(char[] plainText) {
        int[] plainTextWords = new int[4];
        for (int i = 0; i < plainTextWords.length; i++) {
            for (int j = 0; j < 4; j++) {
                plainTextWords[i] += plainText[4 * i + j] * (int) Math.pow(2, 8 * j);
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
        char[] cipherBytes = new char[16];
        for (int i = 0; i < cipherBytes.length; i++) {
            cipherBytes[i] = (char) ((cipherWords[i / 4] >>> 8 * (i % 4)) & 0xFF);
        }
        return cipherBytes;
    }

    int[] fFnunction(int rZero, int rOne, int roundNumber) {
        int tZero = gFunction(rZero);
        int tOne = gFunction(Integer.rotateLeft(rOne, 8));
        int fZero = tZero + tOne + wordsOfExpandedKey[2 * roundNumber + 8];
        int fOne = tZero + 2 * tOne + wordsOfExpandedKey[2 * roundNumber + 9];
        return new int[]{fZero, fOne};
    }

    int gFunction(int x) {
        int[] inputForHFunction = new int[k + 1];
        inputForHFunction[0] = x;
        System.arraycopy(sVector, 0, inputForHFunction, 1, sVector.length);
        return hFunction(inputForHFunction);
    }

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
            sVector[k - 1 - i] = twoFishUtils.multiplyMatrixByVectorModPrimitive(mVector, RS, RS_PRIMITIVE);
        }
    }

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

    int hFunction(int[] words) {
        int x = words[0];
        byte[] bytesOfX = new byte[4];
        for (int i = 0; i < 4; i++) {
            bytesOfX[i] = (byte) (x & 0xFF);
            x >>>= 8;
        }
        byte[][] bytesOfL = new byte[k][4];
        for (int i = 0; i < k; i++) {
            int word = words[i + 1];
            for (int j = 0; j < 4; j++) {
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
                y[1][1] = (byte) (qSubstitution(y[2][1], Q_ONE) ^ bytesOfL[2][1]);
                y[1][2] = (byte) (qSubstitution(y[2][2], Q_ZERO) ^ bytesOfL[2][2]);
                y[1][3] = (byte) (qSubstitution(y[2][3], Q_ZERO) ^ bytesOfL[2][3]);
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

    //TODO оформить вывод, дописать расшифровку, протестить над k=4
    public static void main(String[] args) {

        TwoFish twoFish_k_2 = new TwoFish(new long[]{0, 0});
        char[] plainText = new char[16];
        char[] cipherText = twoFish_k_2.cipherOneBlock(plainText);
        for (int i = 0; i < 48; i++) {
            System.out.println("i: " + (i + 2));
            System.arraycopy(cipherText, 0, plainText, 0, cipherText.length);
            cipherText = twoFish_k_2.cipherOneBlock(plainText);
            StringBuilder result = new StringBuilder();
            StringBuilder plainTextStringBuilder = new StringBuilder();
            for (int k = 0; k < cipherText.length; k++) {
                StringBuilder hex = new StringBuilder(Integer.toHexString(cipherText[k]));
                StringBuilder hexPT = new StringBuilder(Integer.toHexString(plainText[k]));
                if (hex.length() == 1) {
                    hex.insert(0, "0");
                }
                if (hexPT.length() == 1) {
                    hexPT.insert(0, "0");
                }
                result.append(hex);
                plainTextStringBuilder.append(hexPT);
            }
            System.out.println("CT: " + result);
            System.out.println("PT: " + plainTextStringBuilder);
            long leftPartOfKey = 0;
            long rightPartOfKey = 0;
            for (int j = 0; j < plainText.length; j++) {
                if (j < 8) {
                    leftPartOfKey ^= plainText[j];
                    if (j != 7)
                        leftPartOfKey <<= 8;
                } else {
                    rightPartOfKey ^= plainText[j];
                    if (j != 15)
                        rightPartOfKey <<= 8;
                }
            }
            System.out.println("Key: " + Long.toHexString(leftPartOfKey) + Long.toHexString(rightPartOfKey));
            twoFish_k_2 = new TwoFish(new long[]{leftPartOfKey, rightPartOfKey});
        }
    }
}


