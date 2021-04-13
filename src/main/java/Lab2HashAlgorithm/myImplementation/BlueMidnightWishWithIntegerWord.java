package Lab2HashAlgorithm.myImplementation;

import static Lab2HashAlgorithm.myImplementation.BlueMidnightWishDigestSize.BLUE_MIDNIGHT_WISH_224;
import static Lab2HashAlgorithm.myImplementation.BlueMidnightWishDigestSize.BLUE_MIDNIGHT_WISH_256;
import static Utils.CommonUtils.convertByteArrayToIntArrayLittleEndian;
import static Utils.CommonUtils.convertIntArrayToByteArray;

final class BlueMidnightWishWithIntegerWord extends BlueMidnightWishAbstract {
    private final int[] currentDoublePipe;
    private final int[] finalizationConstant;

    {
        finalizationConstant = new int[]{
                0xaaaaaaa0, 0xaaaaaaa1, 0xaaaaaaa2, 0xaaaaaaa3,
                0xaaaaaaa4, 0xaaaaaaa5, 0xaaaaaaa6, 0xaaaaaaa7,
                0xaaaaaaa8, 0xaaaaaaa9, 0xaaaaaaaa, 0xaaaaaaab,
                0xaaaaaaac, 0xaaaaaaad, 0xaaaaaaae, 0xaaaaaaaf};
        currentDoublePipe = new int[16];
    }

    public BlueMidnightWishWithIntegerWord(BlueMidnightWishDigestSize digestSize) {
        super(digestSize);
        initializeInitialDoublePipe();
        if (digestSize == BLUE_MIDNIGHT_WISH_224)
            setOutputLength(28);
        if (digestSize == BLUE_MIDNIGHT_WISH_256)
            setOutputLength(32);
    }

    /**
     * @see BlueMidnightWishAbstract
     */
    @Override
    protected void initializeInitialDoublePipe() {
        if (getDigestSize() == BLUE_MIDNIGHT_WISH_224) {
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
        if (getDigestSize() == BLUE_MIDNIGHT_WISH_256) {
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

    /**
     * @see BlueMidnightWishAbstract
     */
    @Override
    protected byte[] computeHashWithoutResetDoublePipe(byte[] message, long totalLengthOfMessage) {
        int blockSize = getBlockSize();
        byte[] lastBlock = repeatCompressIterationUntilLastBlock(message);
        byte[] paddedMessage = padMessage(lastBlock, 512, totalLengthOfMessage * 8L);
        for (int i = 0; i < paddedMessage.length; i += blockSize) {
            byte[] messageBlock = new byte[blockSize];
            System.arraycopy(paddedMessage, i, messageBlock, 0, blockSize);
            compressIteration(messageBlock);
        }
        int[] finalQuadruplePipeLeftPart = fZeroFunction(currentDoublePipe, finalizationConstant);
        int[] finalFullQuadruplePipe = fOneFunction(currentDoublePipe, finalizationConstant, finalQuadruplePipeLeftPart);
        fTwoFunction(currentDoublePipe, finalFullQuadruplePipe);
        byte[] result = new byte[getOutputLength()];
        int[] reversed = new int[currentDoublePipe.length];
        for (int i = 0; i < reversed.length; i++) {
            reversed[i] = Integer.reverseBytes(currentDoublePipe[i]);
        }
        byte[] currentDoublePipeInBytes = convertIntArrayToByteArray(reversed);
        System.arraycopy(currentDoublePipeInBytes, currentDoublePipeInBytes.length - getOutputLength(), result, 0, result.length);
        return result;
    }

    /**
     * @see BlueMidnightWishAbstract
     */
    @Override
    protected void compressIteration(byte[] messageBlock) {
        int[] messageBlockInLittleEndian = convertByteArrayToIntArrayLittleEndian(messageBlock);
        int[] quadruplePipeLeftPart = fZeroFunction(messageBlockInLittleEndian, currentDoublePipe);
        int[] fullQuadruplePipe = fOneFunction(messageBlockInLittleEndian, currentDoublePipe, quadruplePipeLeftPart);
        fTwoFunction(messageBlockInLittleEndian, fullQuadruplePipe);
    }

    private int[] fZeroFunction(int[] messageBlock, int[] doublePipe) {
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

    private int[] fOneFunction(int[] messageBlock, int[] doublePipe, int[] quadruplePipeLeftPart) {
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

    private void fTwoFunction(int[] messageBlock, int[] quadruplePipe) {
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

    private int addElement(int j, int[] messageBlock, int[] doublePipe) {
        return (Integer.rotateLeft(messageBlock[(j) % 16], (j + 1) % 16 == 0 ? 16 : (j + 1) % 16)
                + Integer.rotateLeft(messageBlock[(j + 3) % 16], (j + 4) % 16 == 0 ? 16 : (j + 4) % 16)
                - Integer.rotateLeft(messageBlock[(j + 10) % 16], (j + 11) % 16 == 0 ? 16 : (j + 11) % 16)
                + 0x05555555 * (j + 16)) ^ doublePipe[(j + 7) % 16];
    }

    private int expandONe(int j, int[] messageBlock, int[] doublePipe, int[] quadruplePipe) {
        return s1(quadruplePipe[j - 16]) + s2(quadruplePipe[j - 15]) + s3(quadruplePipe[j - 14]) + s0(quadruplePipe[j - 13])
                + s1(quadruplePipe[j - 12]) + s2(quadruplePipe[j - 11]) + s3(quadruplePipe[j - 10]) + s0(quadruplePipe[j - 9])
                + s1(quadruplePipe[j - 8]) + s2(quadruplePipe[j - 7]) + s3(quadruplePipe[j - 6]) + s0(quadruplePipe[j - 5])
                + s1(quadruplePipe[j - 4]) + s2(quadruplePipe[j - 3]) + s3(quadruplePipe[j - 2]) + s0(quadruplePipe[j - 1])
                + addElement(j - 16, messageBlock, doublePipe);
    }

    private int expandTwo(int j, int[] messageBlock, int[] doublePipe, int[] quadruplePipe) {
        return quadruplePipe[j - 16] + r1(quadruplePipe[j - 15]) + quadruplePipe[j - 14] + r2(quadruplePipe[j - 13])
                + quadruplePipe[j - 12] + r3(quadruplePipe[j - 11]) + quadruplePipe[j - 10] + r4(quadruplePipe[j - 9])
                + quadruplePipe[j - 8] + r5(quadruplePipe[j - 7]) + quadruplePipe[j - 6] + r6(quadruplePipe[j - 5])
                + quadruplePipe[j - 4] + r7(quadruplePipe[j - 3]) + s4(quadruplePipe[j - 2]) + s5(quadruplePipe[j - 1])
                + addElement(j - 16, messageBlock, doublePipe);
    }
}
