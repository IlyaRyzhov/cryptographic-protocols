package Lab2HashAlgorithm;

import java.util.Arrays;

import static Lab2HashAlgorithm.BlueFishDigestSize.*;
import static Utils.BlueMidnightWishUtils.parseMessageIntoBlocks;
import static Utils.CommonUtils.*;

//TODO подумать, мб отказаться от дженериков, это должно сказаться на производительности
public final class BlueMidnightWishWithIntegerWord extends BlueMidnightWishAbstract {
    private final int[] currentDoublePipe;

    private final int[] finalizationConstant;

    {
        finalizationConstant = new int[]{
                0xaaaaaaa0, 0xaaaaaaa1, 0xaaaaaaa2, 0xaaaaaaa3,
                0xaaaaaaa4, 0xaaaaaaa5, 0xaaaaaaa6, 0xaaaaaaa7,
                0xaaaaaaa8, 0xaaaaaaa9, 0xaaaaaaaa, 0xaaaaaaab,
                0xaaaaaaac, 0xaaaaaaad, 0xaaaaaaae, 0xaaaaaaaf};
    }

    public BlueMidnightWishWithIntegerWord(BlueFishDigestSize digestSize) {
        super(digestSize);
        if (digestSize == BLUE_FISH_224)
            setNumberOfBytesInDigest(28);
        if (digestSize == BLUE_FISH_256)
            setNumberOfBytesInDigest(32);
        currentDoublePipe = new int[16];
        initializeInitialDoublePipe();
    }

    private void initializeInitialDoublePipe() {
        if (getDigestSize() == BLUE_FISH_224) {
            currentDoublePipe[0] = 0x00010203;
            currentDoublePipe[1] = 0x04050607;
            currentDoublePipe[2] = 0x08090A0B;
            currentDoublePipe[3] = 0x0C0D0E0F;
            currentDoublePipe[4] = 0x10111213;
            currentDoublePipe[5] = 0x14151617;
            currentDoublePipe[6] = 0x18191A1B;
            currentDoublePipe[7] = 0x1C1D1E1F;
            currentDoublePipe[8] = 0x20212223;
            currentDoublePipe[9] = 0x24252627;
            currentDoublePipe[10] = 0x28292A2B;
            currentDoublePipe[11] = 0x2C2D2E2F;
            currentDoublePipe[12] = 0x30313233;
            currentDoublePipe[13] = 0x34353637;
            currentDoublePipe[14] = 0x38393A3B;
            currentDoublePipe[15] = 0x3C3D3E3F;

        }
        if (getDigestSize() == BLUE_FISH_256) {
            currentDoublePipe[0] = 0x40414243;
            currentDoublePipe[1] = 0x44454647;
            currentDoublePipe[2] = 0x48494A4B;
            currentDoublePipe[3] = 0x4C4D4E4F;
            currentDoublePipe[4] = 0x50515253;
            currentDoublePipe[5] = 0x54555657;
            currentDoublePipe[6] = 0x58595A5B;
            currentDoublePipe[7] = 0x5C5D5E5F;
            currentDoublePipe[8] = 0x60616263;
            currentDoublePipe[9] = 0x64656667;
            currentDoublePipe[10] = 0x68696A6B;
            currentDoublePipe[11] = 0x6C6D6E6F;
            currentDoublePipe[12] = 0x70717273;
            currentDoublePipe[13] = 0x74757677;
            currentDoublePipe[14] = 0x78797A7B;
            currentDoublePipe[15] = 0x7C7D7E7F;
        }

    }
    private byte[] debugShit() {
        //byte[] paddedMessage = padMessage(message);

        //byte[][] parsedMessage = parseMessageIntoBlocks(paddedMessage, 64);
        int[] mWords = new int[]{0x80636261, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x00000018, 0};

        for (int i = 0; i < 1; i++) {
            //int[] messageBlock = convertByteArrayToIntArrayLittleEndian(parsedMessage[i]);
            int[] quadruplePipeLeftPart = fZeroFunction(mWords, currentDoublePipe);
            int[] fullQuadruplePipe = fOneFunction(mWords, currentDoublePipe, quadruplePipeLeftPart);
            fTwoFunction(mWords, fullQuadruplePipe);
        }
        int[] finalQuadruplePipeLeftPart = fZeroFunction(currentDoublePipe, finalizationConstant);
        int[] finalFullQuadruplePipe = fOneFunction(currentDoublePipe, finalizationConstant, finalQuadruplePipeLeftPart);
        fTwoFunction(currentDoublePipe, finalFullQuadruplePipe);
        byte[] result = new byte[getNumberOfBytesInDigest()];
        int[] reversed = new int[currentDoublePipe.length];
        for (int i = 0; i < reversed.length; i++) {
            reversed[i] = Integer.reverseBytes(currentDoublePipe[i]);
        }
        byte[] currentDoublePipeInBytes = convertIntArrayToByteArray(reversed);
        System.arraycopy(currentDoublePipeInBytes, currentDoublePipeInBytes.length - getNumberOfBytesInDigest(), result, 0, result.length);
        return result;
    }
    //TODO Доделать
    private byte[] computeHashWithoutResetDoublePipe(byte[] message) {
        byte[] paddedMessage = padMessage(message);

        byte[][] parsedMessage = parseMessageIntoBlocks(paddedMessage, 64);
        for (int i = 0; i < parsedMessage.length; i++) {
            int[] messageBlock = convertByteArrayToIntArrayLittleEndian(parsedMessage[i]);
            int[] quadruplePipeLeftPart = fZeroFunction(messageBlock, currentDoublePipe);
            int[] fullQuadruplePipe = fOneFunction(messageBlock, currentDoublePipe, quadruplePipeLeftPart);
            fTwoFunction(messageBlock, fullQuadruplePipe);
        }
        int[] finalQuadruplePipeLeftPart = fZeroFunction(currentDoublePipe, finalizationConstant);
        int[] finalFullQuadruplePipe = fOneFunction(currentDoublePipe, finalizationConstant, finalQuadruplePipeLeftPart);
        fTwoFunction(currentDoublePipe, finalFullQuadruplePipe);
        byte[] result = new byte[getNumberOfBytesInDigest()];
        int[] reversed = new int[currentDoublePipe.length];
        for (int i = 0; i < reversed.length; i++) {
            reversed[i] = Integer.reverseBytes(currentDoublePipe[i]);
        }
        byte[] currentDoublePipeInBytes = convertIntArrayToByteArray(reversed);
        System.arraycopy(currentDoublePipeInBytes, currentDoublePipeInBytes.length - getNumberOfBytesInDigest(), result, 0, result.length);
        return result;
    }

    public byte[] computeHash(byte[] message) {
        byte[] result = computeHashWithoutResetDoublePipe(message);
        initializeInitialDoublePipe();
        return result;
    }

    @Override
    protected byte[] padMessage(byte[] message) {
        long l = message.length * 8L;
        int k = solvePaddingEquation(l);
        byte[] paddingBlockWithoutLastPart = new byte[(k + 1) / 8];
        paddingBlockWithoutLastPart[0] = -128;
        byte[] lastPart = convertLongArrayToByteArray(new long[]{Long.reverseBytes(l)});//менять порядок байтов!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
        int timesOfBlockLength = message.length / 64;
          byte[] resultMessage = new byte[timesOfBlockLength * 64 + 64];
        System.arraycopy(message, 0, resultMessage, 0, message.length);
        System.arraycopy(paddingBlockWithoutLastPart, 0, resultMessage, message.length, paddingBlockWithoutLastPart.length);
        System.arraycopy(lastPart, 0, resultMessage, message.length + paddingBlockWithoutLastPart.length, lastPart.length);
   /*     long l = message.length * 8L;
        int k = solvePaddingEquation(l);
        byte[] paddingBlockWithoutLastPart = new byte[(k + 1) / 8];
        paddingBlockWithoutLastPart[0] = -128;
        byte[] lastPart = convertLongArrayToByteArray(new long[]{Long.reverseBytes(l)});//менять порядок байтов!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
        int timesOfBlockLength = message.length / 64;
        byte[] resultMessage = new byte[timesOfBlockLength * 64 + 64];
        for (int i = 0; i < message.length; i += 4) {
         *//*   byte tmp = message[i];
            message[i] = message[i + 3];
            message[i + 3] = tmp;
            tmp = message[i + 1];
            message[i + 1] = message[i + 2];
            message[i + 2] = tmp;*//*\
            resultMessage[i] = message[i + 3];
            resultMessage[i + 1] = message[i + 2];
            resultMessage[i + 2] = message[i + 1];
            resultMessage[i + 3] = message[i];
        }*/

    /*    System.arraycopy(message, 0, resultMessage, 0, message.length);
        System.arraycopy(paddingBlockWithoutLastPart, 0, resultMessage, message.length, paddingBlockWithoutLastPart.length);
        System.arraycopy(lastPart, 0, resultMessage, message.length + paddingBlockWithoutLastPart.length, lastPart.length);*/
        return resultMessage;
    }

    @Override
    protected int solvePaddingEquation(long lengthOfMessage) {
        int l = (int) (lengthOfMessage % 512);
        int k = 448 - (l + 1);
        return k > 0 ? k : k + 512;
    }

    int[] fZeroFunction(int[] messageBlock, int[] doublePipe) {// правильно +-
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

    //Возвращает всю 4-ную трубу правильно+-
    int[] fOneFunction(int[] messageBlock, int[] doublePipe, int[] quadruplePipeLeftPart) {
        int[] fullQuadruple = new int[32];
        System.arraycopy(quadruplePipeLeftPart, 0, fullQuadruple, 0, quadruplePipeLeftPart.length);
        for (int i = 0; i < getExpandRoundsOne(); i++) {
            fullQuadruple[i + 16] = expandONe(i + 16, messageBlock, doublePipe, fullQuadruple);
        }
        for (int i = getExpandRoundsOne(); i < 16; i++) {
            fullQuadruple[i + 16] = expandTwo(i + 16, messageBlock, doublePipe, fullQuadruple);
        }
        return fullQuadruple;
    }

    //правильно +-
    void fTwoFunction(int[] messageBlock, int[] quadruplePipe) {
        int xL = 0;
        for (int i = 16; i < 24; i++) {
            xL ^= quadruplePipe[i];
        }
        int xH = xL;
        for (int i = 24; i < 32; i++) {
            xH ^= quadruplePipe[i];
        }
        currentDoublePipe[0] = ((xH << 5) ^ (quadruplePipe[16] >>> 5) ^ messageBlock[0]) + (xL ^ quadruplePipe[24] ^ quadruplePipe[0]);
        currentDoublePipe[1] = ((xH >>> 7) ^ (quadruplePipe[17] << 8) ^ messageBlock[1]) + (xL ^ quadruplePipe[25] ^ quadruplePipe[1]);
        currentDoublePipe[2] = ((xH >>> 5) ^ (quadruplePipe[18] << 5) ^ messageBlock[2]) + (xL ^ quadruplePipe[26] ^ quadruplePipe[2]);
        currentDoublePipe[3] = ((xH >>> 1) ^ (quadruplePipe[19] << 5) ^ messageBlock[3]) + (xL ^ quadruplePipe[27] ^ quadruplePipe[3]);
        currentDoublePipe[4] = ((xH >>> 3) ^ (quadruplePipe[20]) ^ messageBlock[4]) + (xL ^ quadruplePipe[28] ^ quadruplePipe[4]);
        currentDoublePipe[5] = ((xH << 6) ^ (quadruplePipe[21] >>> 6) ^ messageBlock[5]) + (xL ^ quadruplePipe[29] ^ quadruplePipe[5]);
        currentDoublePipe[6] = ((xH >>> 4) ^ (quadruplePipe[22] << 6) ^ messageBlock[6]) + (xL ^ quadruplePipe[30] ^ quadruplePipe[6]);
        currentDoublePipe[7] = ((xH >>> 11) ^ (quadruplePipe[23] << 2) ^ messageBlock[7]) + (xL ^ quadruplePipe[31] ^ quadruplePipe[7]);
        currentDoublePipe[8] = Integer.rotateLeft(currentDoublePipe[4], 9) + (xH ^ quadruplePipe[24] ^ messageBlock[8]) + ((xL << 8) ^ quadruplePipe[23] ^ quadruplePipe[8]);
        currentDoublePipe[9] = Integer.rotateLeft(currentDoublePipe[5], 10) + (xH ^ quadruplePipe[25] ^ messageBlock[9]) + ((xL >>> 6) ^ quadruplePipe[16] ^ quadruplePipe[9]);
        currentDoublePipe[10] = Integer.rotateLeft(currentDoublePipe[6], 11) + (xH ^ quadruplePipe[26] ^ messageBlock[10]) + ((xL << 6) ^ quadruplePipe[17] ^ quadruplePipe[10]);
        currentDoublePipe[11] = Integer.rotateLeft(currentDoublePipe[7], 12) + (xH ^ quadruplePipe[27] ^ messageBlock[11]) + ((xL << 4) ^ quadruplePipe[18] ^ quadruplePipe[11]);
        currentDoublePipe[12] = Integer.rotateLeft(currentDoublePipe[0], 13) + (xH ^ quadruplePipe[28] ^ messageBlock[12]) + ((xL >>> 3) ^ quadruplePipe[19] ^ quadruplePipe[12]);
        currentDoublePipe[13] = Integer.rotateLeft(currentDoublePipe[1], 14) + (xH ^ quadruplePipe[29] ^ messageBlock[13]) + ((xL >>> 4) ^ quadruplePipe[20] ^ quadruplePipe[13]);
        currentDoublePipe[14] = Integer.rotateLeft(currentDoublePipe[2], 15) + (xH ^ quadruplePipe[30] ^ messageBlock[14]) + ((xL >>> 7) ^ quadruplePipe[21] ^ quadruplePipe[14]);
        currentDoublePipe[15] = Integer.rotateLeft(currentDoublePipe[3], 16) + (xH ^ quadruplePipe[31] ^ messageBlock[15]) + ((xL >>> 2) ^ quadruplePipe[22] ^ quadruplePipe[15]);
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
        return (x >>> 1) ^ x;
    }


    private int s5(int x) {
        return (x >>> 2) ^ x;
    }

    int addElement(int j, int[] messageBlock, int[] doublePipe) {
        return (Integer.rotateLeft(messageBlock[(j) % 16], (j + 1) % 16 == 0 ? 16 : (j + 1) % 16)
                + Integer.rotateLeft(messageBlock[(j + 3) % 16], (j + 4) % 16 == 0 ? 16 : (j + 4) % 16)
                - Integer.rotateLeft(messageBlock[(j + 10) % 16], (j + 11) % 16 == 0 ? 16 : (j + 11) % 16)
                + 0x05555555 * (j + 16)) ^ doublePipe[(j + 7) % 16];
    }

    int expandONe(int j, int[] messageBlock, int[] doublePipe, int[] quadruplePipe) {
        return s1(quadruplePipe[j - 16]) + s2(quadruplePipe[j - 15]) + s3(quadruplePipe[j - 14]) + s0(quadruplePipe[j - 13])
                + s1(quadruplePipe[j - 12]) + s2(quadruplePipe[j - 11]) + s3(quadruplePipe[j - 10]) + s0(quadruplePipe[j - 9])
                + s1(quadruplePipe[j - 8]) + s2(quadruplePipe[j - 7]) + s3(quadruplePipe[j - 6]) + s0(quadruplePipe[j - 5])
                + s1(quadruplePipe[j - 4]) + s2(quadruplePipe[j - 3]) + s3(quadruplePipe[j - 2]) + s0(quadruplePipe[j - 1])
                + addElement(j - 16, messageBlock, doublePipe);
    }

    int expandTwo(int j, int[] messageBlock, int[] doublePipe, int[] quadruplePipe) {
        return quadruplePipe[j - 16] + r1(quadruplePipe[j - 15]) + quadruplePipe[j - 14] + r2(quadruplePipe[j - 13])
                + quadruplePipe[j - 12] + r3(quadruplePipe[j - 11]) + quadruplePipe[j - 10] + r4(quadruplePipe[j - 9])
                + quadruplePipe[j - 8] + r5(quadruplePipe[j - 7]) + quadruplePipe[j - 6] + r6(quadruplePipe[j - 5])
                + quadruplePipe[j - 4] + r7(quadruplePipe[j - 3]) + s4(quadruplePipe[j - 2]) + s5(quadruplePipe[j - 1])
                + addElement(j - 16, messageBlock, doublePipe);
    }



    public static void main(String[] args) {
/*[36, 102, 7, 121, 42, -46, 98, 84, 48, -56, 30, 44, 78, -95, 56, 10, -35, 91, 8, -5, -128, 117, -38, -19, 79, 64, 29, -68]
24 66 7 79 2a d2 62 54 30 c8 1e 2c 4e a1 38 a dd 5b 8 fb 80 75 da ed 4f 40 1d bc
*/
        /*[114, -122, 93, -45, 27, -30, -20, 90, -96, 49, 43, -56, -98, -4, -33, -41, 71, 2, 54, -68, -37, 28, 13, -94, 108, -31, -36, 23]
72 86 5d d3 1b e2 ec 5a a0 31 2b c8 9e fc df d7 47 2 36 bc db 1c d a2 6c e1 dc 17 */
        /*[74, 30, -22, 25, -49, 29, 90, 33, 81, 36, -87, -69, 62, -92, -11, 39, 15, 122, 5, 57, -28, 105, 1, 0, 114, 117, 121, 113]
4a 1e ea 19 cf 1d 5a 21 51 24 a9 bb 3e a4 f5 27 f 7a 5 39 e4 69 1 0 72 75 79 71 */
        /*[-42, 70, -79, 57, -104, -99, -19, 92, -77, 123, -45, 48, 18, 113, -11, -13, 32, -25, 41, 74, -54, 54, -12, 5, -75, 89, 105, 22]
d6 46 b1 39 98 9d ed 5c b3 7b d3 30 12 71 f5 f3 20 e7 29 4a ca 36 f4 5 b5 59 69 16 */
        BlueMidnightWishWithIntegerWord blueMidnightWishWithIntegerWord = new BlueMidnightWishWithIntegerWord(BLUE_FISH_256);
        /*[109, 61, 46, -94, 125, 20, -6, 37, 80, 111, -53, -124, -17, 11, -128, -98, 55, 29, 119, 97, 79, 78, -110, -23, 53, -42, 96, -34, -34, 84, -5, -127]
6d 3d 2e a2 7d 14 fa 25 50 6f cb 84 ef b 80 9e 37 1d 77 61 4f 4e 92 e9 35 d6 60 de de 54 fb 81 */
        /*[40, 67, 85, -88, -57, -120, 16, -124, 101, -77, -24, -61, -48, -60, -94, -97, -43, -111, -21, -36, 121, 126, 40, -91, -90, 79, 28, 93, 93, 45, -43, 45]
28 43 55 a8 c7 88 10 84 65 b3 e8 c3 d0 c4 a2 9f d5 91 eb dc 79 7e 28 a5 a6 4f 1c 5d 5d 2d d5 2d */
        byte[] arr = new byte[10];
        arr[0] = 'a';
        arr[1] = 'b';
        arr[2] = 'c';
        Arrays.fill(arr, (byte) 0x15);
        System.out.println(Arrays.toString(blueMidnightWishWithIntegerWord.computeHash(arr)));
        //   byte[] mas=blueMidnightWishWithIntegerWord.computeHashWithoutResetDoublePipe(arr);
        byte[] mas = blueMidnightWishWithIntegerWord.debugShit();
        for (int i = 0; i < mas.length; i++) {
            System.out.print(Integer.toHexString(mas[i] & 0xff) + " ");
        }
        System.out.println();

    }

}
