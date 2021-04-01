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
/*User (odd, even) keys  --> S-Box keys:
0x322C12F6  0x5C9F589F --> 0x149C8A18
0x5AC3E82A  0x2FECBFB6 --> 0xDC538B81

Round keys:
0x6A82F19B  0x509B2202
0x78EA11EA  0xA1980BAE
0x1FA27EF5  0x78F305E0
0x984D4B31  0x6F8DA8C9
0x2FA295F5  0xCACAC6B3
0xD76E1622  0x11A04725
0x20138AA3  0x0E351308
0x54481A28  0x24FADDA0
0x0C63C319  0xCCB2C05B
0xE2F042D5  0xE9158B9F
0x4CDF657B  0x36E28921
0xFCB3D025  0xA66E1EEB
0x19460597  0x77F0F7CC
0x8A2DB2D5  0x10593266
0x3936CBFD  0x91BA53D8
0xB8592DFD  0x49AF519C
0xA2035716  0x62F8ABBD
0xF413E86A  0x36D0D8F3
0xCCCBFFE4  0x1F4460FD
0x38FDDFAA  0xEBC1F456

<== Twofish_Algorithm.makeKey()
==> Twofish_Algorithm.blockEncrypt([B@3ffc5af1, 0, [Ljava.lang.Object;@5e5792a0)
PT=D491DB16E7B1C39E86CB086B789F5419
PTw=7C59604FCE5893E513E2DA6CB8CC94D6
t0: 369402942 t1: 1569100539
CT0=7C59604FCE5893E558678BA1EA45B94A
t0: -1609597041 t1: -459757290
CT1=1027AF44E6503F2B58678BA1EA45B94A
t0: 715019879 t1: -960288289
CT2=1027AF44E6503F2B248940A412D2CFB8
t0: -698205827 t1: 1198495757
CT3=311F227B469C3960248940A412D2CFB8
t0: -1277823115 t1: 1885488341
CT4=311F227B469C39608A095FE344E8DE0A
t0: -574490284 t1: -55505174
CT5=463E34B44D01D0078A095FE344E8DE0A
t0: -996624009 t1: 830232136
CT6=463E34B44D01D007E47E956CD7A2533C
t0: -259925028 t1: 1976408099
CT7=129EB84818888B03E47E956CD7A2533C
t0: -1546326113 t1: -636143531
CT8=129EB84818888B03B9A75C7360B4FE6C
t0: 928077003 t1: -1922375362
CT9=2E3BA84B53915FABB9A75C7360B4FE6C
t0: -2142281888 t1: -1379134802
CT10=2E3BA84B53915FAB6F7AB13CACC8244C
t0: -2121272164 t1: 804528679
CT11=A3F376458C0535D06F7AB13CACC8244C
t0: 157616814 t1: -1757834088
CT12=A3F376458C0535D016EDA3B0C3409702
t0: -566969873 t1: -1267653023
CT13=92A55F7F65EDB40516EDA3B0C3409702
t0: 2138695082 t1: -296584502
CT14=92A55F7F65EDB405163AE1F4FDE2123E
t0: -578188145 t1: -818860086
CT15=3B8EE1BEAC768873163AE1F4FDE2123E
CTw=A3C3AA8FC3FB20BA09989F01851117DE
CT=019F9809DE1711858FAAC3A3BA20FBC3

<== Twofish_Algorithm.blockEncrypt()

Process finished with exit code 0
*/

    //Неправильно
//TODO Не работате I=3
    /*User (odd, even) keys  --> S-Box keys:
<== Twofish_Algorithm.makeKey()
==> Twofish_Algorithm.blockEncrypt([B@548e7350, 0, [Ljava.lang.Object;@1a968a59)
0x462EA36E  0x55B73BD4 --> 0x42DECDAD
0x0D4E5BD4  0xB782A2F2 --> 0x0F8E3CE2
0x1B2CC94D  0x9D73FF57 --> 0x1B016E6E
0x6F21C80C  0x7001FCD7 --> 0x10CD15C7
    Round keys:
0xA354793D  0x6E1A33F0
0x6AB01A83  0x7DF52A97
0x12FBC877  0xD427152A
0xCF9EB934  0x69F6E699
0x3CE0B947  0x7C5AB06D
0x66D41AD8  0x4E9F86DD
0xD25F6999  0xA3A35380
0x5C7CC0E2  0x27517CE9
0x9C43A538  0xB58D216A
0x49136074  0x4053FA28
0x8DD37CAC  0x2D732874
0x725E993F  0x3F874A31
0xC06B1D66  0xB3045D42
0x69A78BF1  0x318E9035
0x795D6178  0x7692A11C
0xCF239AE9  0xBAFEB974
0x8926908B  0xFFFC400D
0x16A21CF1  0xEC65CFB2
0x22AD4541  0x01A0F21F
0x08FE84AB  0xEF282332*/
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
            // cipherBytes[i] = (char) ((cipherWords[i / 4] / (int) Math.pow(2, 8 * (i % 4))) & 0xFF);
            cipherBytes[i] = (char) ((cipherWords[i / 4] >>> 8 * (i % 4)) & 0xFF);
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

    //Скорее всего не работает
    //Todo попробоват подавать разные xi в h, получить вектор y и умножить
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
            sVector[k - 1 - i] = twoFishUtils.multiplyMatrixByVectorModPrimitive(mVector, RS, RS_PRIMITIVE);//svector[i]
        }
    }

    //Работает
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
/*        TwoFish twoFish2 = new TwoFish(new long[]{0xD43BB7556EA32E46L,0xF2A282B7D45B4E0DL,0x57FF739D4DC92C1BL,0xD7FC01700CC8216FL});
        char[] cipherBytes = twoFish2.cipherOneBlock(new char[]{0xd4,0x91,0xdb,0x16,0xe7,0xb1,0xc3,0x9e,0x86,0xcb,0x08,0x6b,0x78,0x9f,0x54,0x19});
*//*        TwoFish twoFish2= new TwoFish(new long[]{0,0});
        char[] cipherBytes=twoFish2.cipherOneBlock(new char[16]);*//*
        StringBuilder string2 = new StringBuilder();
        for (int i = 0; i < cipherBytes.length; i++) {
            //   string2.append(Integer.toHexString(Byte.toUnsignedInt(cipherBytes[i])));
            StringBuilder hex = new StringBuilder(Integer.toHexString(cipherBytes[i]));
            if (hex.length() == 1) {
                hex.insert(0, "0");
            }
            string2.append(hex);
        }
        System.out.println(string2.toString());*/
      /*  System.out.println(string2.toString().toUpperCase().equals("D491DB16E7B1C39E86CB086B789F5419")); //ne rabotaet
        TwoFish twoFish_k_2 = new TwoFish(new long[]{0, 0});
        char[] plainText = new char[]{0xd4, 0x91, 0xdb, 0x16, 0xe7, 0xb1, 0xc3, 0x9e, 0x86, 0xcb, 0x08, 0x6b, 0x78, 0x9f, 0x54, 0x19};
        char[] cipherText = twoFish_k_2.cipherOneBlock(plainText);
        for (int k = 0; k < cipherText.length; k++) {
            StringBuilder hex = new StringBuilder(Integer.toHexString(cipherText[k]));
            StringBuilder hexPT = new StringBuilder(Integer.toHexString(plainText[k]));
            if (hex.length() == 1) {
                hex.insert(0, "0");
            }
            if (hexPT.length() == 1) {
                hexPT.insert(0, "0");
            }
            string2.append(hex);
            //plainTextStringBuilder.append(hexPT);
        }*/
        /*System.out.println(string2);
        new TwoFish(new long[]{0x9f589f5cf6122c32L, 0xb6bfec2f2ae8c35aL}).cipherOneBlock(new char[]{0xd4, 0x91, 0xdb, 0x16, 0xe7, 0xb1, 0xc3, 0x9e, 0x86, 0xcb, 0x08, 0x6b, 0x78, 0x9f, 0x54, 0x19});*/
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


