package Lab2HashAlgorithm;

import java.util.Arrays;

import static Lab2HashAlgorithm.BlueFishDigestSize.BLUE_FISH_224;
import static Lab2HashAlgorithm.BlueFishDigestSize.BLUE_FISH_256;
import static Utils.BlueMidnightWishUtils.parseMessageIntoBlocks;
import static Utils.CommonUtils.convertByteArrayToInt;
import static Utils.CommonUtils.convertLongArrayToByteArray;

//TODO подумать, мб отказаться от дженериков, это должно сказаться на производительности
public final class BlueMidnightWishWithIntegerWord extends BlueMidnightWishAbstract {
    private final int[] hTable;

    public BlueMidnightWishWithIntegerWord(BlueFishDigestSize digestSize) {
        super(digestSize);
        hTable = new int[16];
        initializeInitialDoublePipe();
    }

    private void initializeInitialDoublePipe() {
        if (getDigestSize() == BLUE_FISH_224) {
            hTable[0] = 0x00010203;
            hTable[1] = 0x04050607;
            hTable[2] = 0x08090A0B;
            hTable[3] = 0x0C0D0E0F;
            hTable[4] = 0x10111213;
            hTable[5] = 0x14151617;
            hTable[6] = 0x18191A1B;
            hTable[7] = 0x1C1D1E1F;
            hTable[8] = 0x20212223;
            hTable[9] = 0x24252627;
            hTable[10] = 0x28292A2B;
            hTable[11] = 0x2C2D2E2F;
            hTable[12] = 0x30313233;
            hTable[13] = 0x34353637;
            hTable[14] = 0x38393A3B;
            hTable[15] = 0x3C3D3E3F;

        }
        if (getDigestSize() == BLUE_FISH_256) {
            hTable[0] = 0x40414243;
            hTable[1] = 0x44454647;
            hTable[2] = 0x48494A4B;
            hTable[3] = 0x4C4D4E4F;
            hTable[4] = 0x50515253;
            hTable[5] = 0x54555657;
            hTable[6] = 0x58595A5B;
            hTable[7] = 0x5C5D5E5F;
            hTable[8] = 0x60616263;
            hTable[9] = 0x64656667;
            hTable[10] = 0x68696A6B;
            hTable[11] = 0x6C6D6E6F;
            hTable[12] = 0x70717273;
            hTable[13] = 0x74757677;
            hTable[14] = 0x78797A7B;
            hTable[15] = 0x7C7D7E7F;
        }
        //   setInitialDoublePipe(hTable);
    }

    @Override
    protected byte[] padMessage(byte[] message) {
        long l = message.length * 8L;
        int k = solvePaddingEquation(l);
        byte[] paddingBlockWithoutLastPart = new byte[(k + 1) / 8];
        paddingBlockWithoutLastPart[0] = -128;
        byte[] lastPart = convertLongArrayToByteArray(new long[]{l});//менять порядок байтов
        int timesOfBlockLength = message.length / 64;
        byte[] resultMessage = new byte[timesOfBlockLength * 64 + 64];
        System.arraycopy(message, 0, resultMessage, 0, message.length);
        System.arraycopy(paddingBlockWithoutLastPart, 0, resultMessage, message.length, paddingBlockWithoutLastPart.length);
        System.arraycopy(lastPart, 0, resultMessage, message.length + paddingBlockWithoutLastPart.length, lastPart.length);
        return resultMessage;
    }

    @Override
    protected int solvePaddingEquation(long lengthOfMessage) {
        int l = (int) (lengthOfMessage % 512);
        int k = 448 - (l + 1);
        return k > 0 ? k : k + 512;
    }

    // вынести в абстрактный класс
    int[] fZeroFunction(int[] messageBlock, int[] doublePipe) {
        int W0 = (messageBlock[5] ^ doublePipe[5]) - (messageBlock[7] ^ doublePipe[7]) + (messageBlock[10] ^ doublePipe[10]) + (messageBlock[13] ^ doublePipe[13]) + (messageBlock[14] ^ doublePipe[14]);
        int W1 = (messageBlock[6] ^ doublePipe[6]) - (messageBlock[8] ^ doublePipe[8]) + (messageBlock[11] ^ doublePipe[11]) + (messageBlock[14] ^ doublePipe[14]) - (messageBlock[15] ^ doublePipe[15]);
        int W2 = (messageBlock[0] ^ doublePipe[0]) + (messageBlock[7] ^ doublePipe[7]) + (messageBlock[9] ^ doublePipe[9]) - (messageBlock[12] ^ doublePipe[12]) + (messageBlock[15] ^ doublePipe[15]);
        int W3 = (messageBlock[0] ^ doublePipe[0]) - (messageBlock[1] ^ doublePipe[1]) + (messageBlock[8] ^ doublePipe[8]) - (messageBlock[10] ^ doublePipe[10]) + (messageBlock[13] ^ doublePipe[13]);
        int W4 = (messageBlock[1] ^ doublePipe[1]) + (messageBlock[2] ^ doublePipe[2]) + (messageBlock[9] ^ doublePipe[9]) - (messageBlock[11] ^ doublePipe[11]) - (messageBlock[14] ^ doublePipe[14]);
        int W5 = (messageBlock[3] ^ doublePipe[3]) - (messageBlock[2] ^ doublePipe[2]) + (messageBlock[10] ^ doublePipe[10]) - (messageBlock[12] ^ doublePipe[12]) + (messageBlock[15] ^ doublePipe[15]);
        int W6 = (messageBlock[4] ^ doublePipe[4]) - (messageBlock[0] ^ doublePipe[0]) - (messageBlock[3] ^ doublePipe[3]) - (messageBlock[11] ^ doublePipe[11]) + (messageBlock[13] ^ doublePipe[13]);
        int W7 = (messageBlock[1] ^ doublePipe[1]) - (messageBlock[4] ^ doublePipe[4]) - (messageBlock[5] ^ doublePipe[5]) - (messageBlock[12] ^ doublePipe[12]) - (messageBlock[14] ^ doublePipe[14]);
        int W8 = (messageBlock[2] ^ doublePipe[2]) - (messageBlock[5] ^ doublePipe[5]) - (messageBlock[6] ^ doublePipe[6]) + (messageBlock[13] ^ doublePipe[13]) - (messageBlock[15] ^ doublePipe[15]);
        int W9 = (messageBlock[0] ^ doublePipe[0]) - (messageBlock[3] ^ doublePipe[3]) + (messageBlock[6] ^ doublePipe[6]) - (messageBlock[7] ^ doublePipe[7]) + (messageBlock[14] ^ doublePipe[14]);
        int W10 = (messageBlock[8] ^ doublePipe[8]) - (messageBlock[1] ^ doublePipe[1]) - (messageBlock[4] ^ doublePipe[4]) - (messageBlock[7] ^ doublePipe[7]) + (messageBlock[15] ^ doublePipe[15]);
        int W11 = (messageBlock[8] ^ doublePipe[8]) - (messageBlock[0] ^ doublePipe[0]) - (messageBlock[2] ^ doublePipe[2]) - (messageBlock[5] ^ doublePipe[5]) + (messageBlock[9] ^ doublePipe[9]);
        int W12 = (messageBlock[1] ^ doublePipe[1]) + (messageBlock[3] ^ doublePipe[3]) - (messageBlock[6] ^ doublePipe[6]) - (messageBlock[9] ^ doublePipe[9]) + (messageBlock[10] ^ doublePipe[10]);
        int W13 = (messageBlock[2] ^ doublePipe[2]) + (messageBlock[4] ^ doublePipe[4]) + (messageBlock[7] ^ doublePipe[7]) + (messageBlock[10] ^ doublePipe[10]) + (messageBlock[11] ^ doublePipe[11]);
        int W14 = (messageBlock[3] ^ doublePipe[3]) - (messageBlock[5] ^ doublePipe[5]) + (messageBlock[8] ^ doublePipe[8]) - (messageBlock[11] ^ doublePipe[11]) - (messageBlock[12] ^ doublePipe[12]);
        int W15 = (messageBlock[12] ^ doublePipe[12]) - (messageBlock[4] ^ doublePipe[4]) - (messageBlock[6] ^ doublePipe[6]) - (messageBlock[9] ^ doublePipe[9]) + (messageBlock[13] ^ doublePipe[13]);
        int Q0 = s0(W0) + doublePipe[1];
        int Q1 = s1(W1) + doublePipe[2];
        int Q2 = s2(W2) + doublePipe[3];
        int Q3 = s3(W3) + doublePipe[4];
        int Q4 = s4(W4) + doublePipe[5];
        int Q5 = s0(W5) + doublePipe[6];
        int Q6 = s1(W6) + doublePipe[7];
        int Q7 = s2(W7) + doublePipe[8];
        int Q8 = s3(W8) + doublePipe[9];
        int Q9 = s4(W9) + doublePipe[10];
        int Q10 = s0(W10) + doublePipe[11];
        int Q11 = s1(W11) + doublePipe[12];
        int Q12 = s2(W12) + doublePipe[13];
        int Q13 = s3(W13) + doublePipe[14];
        int Q14 = s4(W14) + doublePipe[15];
        int Q15 = s0(W15) + doublePipe[0];
        return new int[]{Q0, Q1, Q2, Q3, Q4, Q5, Q6, Q7, Q8, Q9, Q10, Q11, Q12, Q13, Q14, Q15};
    }

    private int r1(int x) {
        return Integer.rotateLeft(x, 3);
    }


    private int r2(int x) {
        return Integer.rotateLeft(x, 7);
    }


    private int r3(int x) {
        return Integer.rotateLeft(x, 13);
    }


    private int r4(int x) {
        return Integer.rotateLeft(x, 16);
    }


    private int r5(int x) {
        return Integer.rotateLeft(x, 19);
    }


    private int r6(int x) {
        return Integer.rotateLeft(x, 23);
    }


    private int r7(int x) {
        return Integer.rotateLeft(x, 27);
    }


    private int s0(int x) {
        return (x >>> 1) ^ (x << 3) ^ Integer.rotateLeft(x, 4) ^ Integer.rotateLeft(x, 19);
    }


    private int s1(int x) {
        return (x >>> 1) ^ (x << 2) ^ Integer.rotateLeft(x, 8) ^ Integer.rotateLeft(x, 23);
    }


    private int s2(int x) {
        return (x >>> 2) ^ (x << 1) ^ Integer.rotateLeft(x, 12) ^ Integer.rotateLeft(x, 25);
    }


    private int s3(int x) {
        return (x >>> 2) ^ (x << 2) ^ Integer.rotateLeft(x, 15) ^ Integer.rotateLeft(x, 29);
    }


    private int s4(int x) {
        System.out.println(hTable[9]);
        return (x >>> 1) ^ x;
    }


    private int s5(int x) {
        return (x >>> 2) ^ x;
    }

    public static void main(String[] args) {

        BlueMidnightWishWithIntegerWord blueMidnightWishWithIntegerWord = new BlueMidnightWishWithIntegerWord(BLUE_FISH_224);
        System.out.println(blueMidnightWishWithIntegerWord.solvePaddingEquation(504));
        System.out.println(Integer.toBinaryString(-128 & 0xff));
        System.out.println(Byte.parseByte("-10000000", 2));
        byte[] mes = new byte[3];
        mes[0] = 'a';
        mes[1] = 'b';
        mes[2] = 'c';
        int c = '1';
        System.out.println(Arrays.toString(blueMidnightWishWithIntegerWord.padMessage(mes)));
        //      System.out.println(blueMidnightWishWithIntegerWord.padMessage(mes).length);
        byte[][] messsage = parseMessageIntoBlocks(blueMidnightWishWithIntegerWord.padMessage(mes), 64);

        for (int i = 0; i < messsage[0].length; i++) {
            System.out.print(Integer.toHexString(messsage[0][i] & 0xff) + " ");
        }
        System.out.println();
        for (int i = 0; i < messsage.length; i++) {
            for (int j = 0; j < messsage[i].length; j += 4) {
                byte[] numBytes = Arrays.copyOfRange(messsage[i], j, j + 4);
                System.out.print(Integer.toHexString(Integer.reverseBytes(convertByteArrayToInt(numBytes))) + " ");
            }
        }

    }

}
