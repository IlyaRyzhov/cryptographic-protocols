package Lab2HashAlgorithm.myImplementation;

import static Lab2HashAlgorithm.myImplementation.BlueMidnightWishDigestSize.BLUE_MIDNIGHT_WISH_384;
import static Lab2HashAlgorithm.myImplementation.BlueMidnightWishDigestSize.BLUE_MIDNIGHT_WISH_512;
import static Utils.CommonUtils.convertByteArrayToLongArrayLittleEndian;
import static Utils.CommonUtils.convertLongArrayToByteArray;

final class BlueMidnightWishWithLongWord extends BlueMidnightWishAbstract {
    private final long[] currentDoublePipe;
    private final long[] finalizationConstant;

    {
        finalizationConstant = new long[]{
                0xaaaaaaaaaaaaaaa0L, 0xaaaaaaaaaaaaaaa1L, 0xaaaaaaaaaaaaaaa2L,
                0xaaaaaaaaaaaaaaa3L, 0xaaaaaaaaaaaaaaa4L, 0xaaaaaaaaaaaaaaa5L,
                0xaaaaaaaaaaaaaaa6L, 0xaaaaaaaaaaaaaaa7L, 0xaaaaaaaaaaaaaaa8L,
                0xaaaaaaaaaaaaaaa9L, 0xaaaaaaaaaaaaaaaaL, 0xaaaaaaaaaaaaaaabL,
                0xaaaaaaaaaaaaaaacL, 0xaaaaaaaaaaaaaaadL, 0xaaaaaaaaaaaaaaaeL,
                0xaaaaaaaaaaaaaaafL};
        currentDoublePipe = new long[16];
    }

    public BlueMidnightWishWithLongWord(BlueMidnightWishDigestSize digestSize) {
        super(digestSize);
        initializeInitialDoublePipe();
        if (digestSize == BLUE_MIDNIGHT_WISH_384)
            setOutputLength(48);
        if (digestSize == BLUE_MIDNIGHT_WISH_512)
            setOutputLength(64);
    }

    /**
     * @see BlueMidnightWishAbstract
     */
    @Override
    protected void initializeInitialDoublePipe() {
        if (getDigestSize() == BLUE_MIDNIGHT_WISH_384) {
            currentDoublePipe[0] = 0x0001020304050607L;
            currentDoublePipe[1] = 0x08090A0B0C0D0E0FL;
            currentDoublePipe[2] = 0x1011121314151617L;
            currentDoublePipe[3] = 0x18191A1B1C1D1E1FL;
            currentDoublePipe[4] = 0x2021222324252627L;
            currentDoublePipe[5] = 0x28292A2B2C2D2E2FL;
            currentDoublePipe[6] = 0x3031323334353637L;
            currentDoublePipe[7] = 0x38393A3B3C3D3E3FL;
            currentDoublePipe[8] = 0x4041424344454647L;
            currentDoublePipe[9] = 0x48494A4B4C4D4E4FL;
            currentDoublePipe[10] = 0x5051525354555657L;
            currentDoublePipe[11] = 0x58595A5B5C5D5E5FL;
            currentDoublePipe[12] = 0x6061626364656667L;
            currentDoublePipe[13] = 0x68696A6B6C6D6E6FL;
            currentDoublePipe[14] = 0x7071727374757677L;
            currentDoublePipe[15] = 0x78797A7B7C7D7E7FL;
        }
        if (getDigestSize() == BLUE_MIDNIGHT_WISH_512) {
            currentDoublePipe[0] = 0x8081828384858687L;
            currentDoublePipe[1] = 0x88898A8B8C8D8E8FL;
            currentDoublePipe[2] = 0x9091929394959697L;
            currentDoublePipe[3] = 0x98999A9B9C9D9E9FL;
            currentDoublePipe[4] = 0xA0A1A2A3A4A5A6A7L;
            currentDoublePipe[5] = 0xA8A9AAABACADAEAFL;
            currentDoublePipe[6] = 0xB0B1B2B3B4B5B6B7L;
            currentDoublePipe[7] = 0xB8B9BABBBCBDBEBFL;
            currentDoublePipe[8] = 0xC0C1C2C3C4C5C6C7L;
            currentDoublePipe[9] = 0xC8C9CACBCCCDCECFL;
            currentDoublePipe[10] = 0xD0D1D2D3D4D5D6D7L;
            currentDoublePipe[11] = 0xD8D9DADBDCDDDEDFL;
            currentDoublePipe[12] = 0xE0E1E2E3E4E5E6E7L;
            currentDoublePipe[13] = 0xE8E9EAEBECEDEEEFL;
            currentDoublePipe[14] = 0xF0F1F2F3F4F5F6F7L;
            currentDoublePipe[15] = 0xF8F9FAFBFCFDFEFFL;
        }
    }

    /**
     * @see BlueMidnightWishAbstract
     */
    @Override
    protected byte[] computeHashWithoutResetDoublePipe(byte[] message, long totalLengthOfMessage) {
        int blockSize = getBlockSize();
        byte[] lastBlock = repeatCompressIterationUntilLastBlock(message);
        byte[] paddedMessage = padMessage(lastBlock, 1024, totalLengthOfMessage * 8L);
        for (int i = 0; i < paddedMessage.length; i += blockSize) {
            byte[] messageBlock = new byte[blockSize];
            System.arraycopy(paddedMessage, i, messageBlock, 0, blockSize);
            compressIteration(messageBlock);
        }
        long[] finalQuadruplePipeLeftPart = fZeroFunction(currentDoublePipe, finalizationConstant);
        long[] finalFullQuadruplePipe = fOneFunction(currentDoublePipe, finalizationConstant, finalQuadruplePipeLeftPart);
        fTwoFunction(currentDoublePipe, finalFullQuadruplePipe);
        byte[] result = new byte[getOutputLength()];
        long[] reversed = new long[currentDoublePipe.length];
        for (int i = 0; i < reversed.length; i++) {
            reversed[i] = Long.reverseBytes(currentDoublePipe[i]);
        }
        byte[] currentDoublePipeInBytes = convertLongArrayToByteArray(reversed);
        System.arraycopy(currentDoublePipeInBytes, currentDoublePipeInBytes.length - getOutputLength(), result, 0, result.length);
        return result;
    }

    /**
     * @see BlueMidnightWishAbstract
     */
    @Override
    protected void compressIteration(byte[] messageBlock) {
        long[] messageBlockInLittleEndian = convertByteArrayToLongArrayLittleEndian(messageBlock);
        long[] quadruplePipeLeftPart = fZeroFunction(messageBlockInLittleEndian, currentDoublePipe);
        long[] fullQuadruplePipe = fOneFunction(messageBlockInLittleEndian, currentDoublePipe, quadruplePipeLeftPart);
        fTwoFunction(messageBlockInLittleEndian, fullQuadruplePipe);
    }

    private long[] fZeroFunction(long[] messageBlock, long[] doublePipe) {
        long W0 = (messageBlock[5] ^ doublePipe[5]) - (messageBlock[7] ^ doublePipe[7]) + (messageBlock[10] ^ doublePipe[10]) + (messageBlock[13] ^ doublePipe[13]) + (messageBlock[14] ^ doublePipe[14]);
        long W1 = (messageBlock[6] ^ doublePipe[6]) - (messageBlock[8] ^ doublePipe[8]) + (messageBlock[11] ^ doublePipe[11]) + (messageBlock[14] ^ doublePipe[14]) - (messageBlock[15] ^ doublePipe[15]);
        long W2 = (messageBlock[0] ^ doublePipe[0]) + (messageBlock[7] ^ doublePipe[7]) + (messageBlock[9] ^ doublePipe[9]) - (messageBlock[12] ^ doublePipe[12]) + (messageBlock[15] ^ doublePipe[15]);
        long W3 = (messageBlock[0] ^ doublePipe[0]) - (messageBlock[1] ^ doublePipe[1]) + (messageBlock[8] ^ doublePipe[8]) - (messageBlock[10] ^ doublePipe[10]) + (messageBlock[13] ^ doublePipe[13]);
        long W4 = (messageBlock[1] ^ doublePipe[1]) + (messageBlock[2] ^ doublePipe[2]) + (messageBlock[9] ^ doublePipe[9]) - (messageBlock[11] ^ doublePipe[11]) - (messageBlock[14] ^ doublePipe[14]);
        long W5 = (messageBlock[3] ^ doublePipe[3]) - (messageBlock[2] ^ doublePipe[2]) + (messageBlock[10] ^ doublePipe[10]) - (messageBlock[12] ^ doublePipe[12]) + (messageBlock[15] ^ doublePipe[15]);
        long W6 = (messageBlock[4] ^ doublePipe[4]) - (messageBlock[0] ^ doublePipe[0]) - (messageBlock[3] ^ doublePipe[3]) - (messageBlock[11] ^ doublePipe[11]) + (messageBlock[13] ^ doublePipe[13]);
        long W7 = (messageBlock[1] ^ doublePipe[1]) - (messageBlock[4] ^ doublePipe[4]) - (messageBlock[5] ^ doublePipe[5]) - (messageBlock[12] ^ doublePipe[12]) - (messageBlock[14] ^ doublePipe[14]);
        long W8 = (messageBlock[2] ^ doublePipe[2]) - (messageBlock[5] ^ doublePipe[5]) - (messageBlock[6] ^ doublePipe[6]) + (messageBlock[13] ^ doublePipe[13]) - (messageBlock[15] ^ doublePipe[15]);
        long W9 = (messageBlock[0] ^ doublePipe[0]) - (messageBlock[3] ^ doublePipe[3]) + (messageBlock[6] ^ doublePipe[6]) - (messageBlock[7] ^ doublePipe[7]) + (messageBlock[14] ^ doublePipe[14]);
        long W10 = (messageBlock[8] ^ doublePipe[8]) - (messageBlock[1] ^ doublePipe[1]) - (messageBlock[4] ^ doublePipe[4]) - (messageBlock[7] ^ doublePipe[7]) + (messageBlock[15] ^ doublePipe[15]);
        long W11 = (messageBlock[8] ^ doublePipe[8]) - (messageBlock[0] ^ doublePipe[0]) - (messageBlock[2] ^ doublePipe[2]) - (messageBlock[5] ^ doublePipe[5]) + (messageBlock[9] ^ doublePipe[9]);
        long W12 = (messageBlock[1] ^ doublePipe[1]) + (messageBlock[3] ^ doublePipe[3]) - (messageBlock[6] ^ doublePipe[6]) - (messageBlock[9] ^ doublePipe[9]) + (messageBlock[10] ^ doublePipe[10]);
        long W13 = (messageBlock[2] ^ doublePipe[2]) + (messageBlock[4] ^ doublePipe[4]) + (messageBlock[7] ^ doublePipe[7]) + (messageBlock[10] ^ doublePipe[10]) + (messageBlock[11] ^ doublePipe[11]);
        long W14 = (messageBlock[3] ^ doublePipe[3]) - (messageBlock[5] ^ doublePipe[5]) + (messageBlock[8] ^ doublePipe[8]) - (messageBlock[11] ^ doublePipe[11]) - (messageBlock[12] ^ doublePipe[12]);
        long W15 = (messageBlock[12] ^ doublePipe[12]) - (messageBlock[4] ^ doublePipe[4]) - (messageBlock[6] ^ doublePipe[6]) - (messageBlock[9] ^ doublePipe[9]) + (messageBlock[13] ^ doublePipe[13]);
        long Q0 = s0(W0) + doublePipe[1];
        long Q1 = s1(W1) + doublePipe[2];
        long Q2 = s2(W2) + doublePipe[3];
        long Q3 = s3(W3) + doublePipe[4];
        long Q4 = s4(W4) + doublePipe[5];
        long Q5 = s0(W5) + doublePipe[6];
        long Q6 = s1(W6) + doublePipe[7];
        long Q7 = s2(W7) + doublePipe[8];
        long Q8 = s3(W8) + doublePipe[9];
        long Q9 = s4(W9) + doublePipe[10];
        long Q10 = s0(W10) + doublePipe[11];
        long Q11 = s1(W11) + doublePipe[12];
        long Q12 = s2(W12) + doublePipe[13];
        long Q13 = s3(W13) + doublePipe[14];
        long Q14 = s4(W14) + doublePipe[15];
        long Q15 = s0(W15) + doublePipe[0];
        return new long[]{Q0, Q1, Q2, Q3, Q4, Q5, Q6, Q7, Q8, Q9, Q10, Q11, Q12, Q13, Q14, Q15};
    }

    private long[] fOneFunction(long[] messageBlock, long[] doublePipe, long[] quadruplePipeLeftPart) {
        long[] fullQuadruple = new long[32];
        System.arraycopy(quadruplePipeLeftPart, 0, fullQuadruple, 0, quadruplePipeLeftPart.length);
        for (int i = 0; i < getExpandRoundsOne(); i++) {
            fullQuadruple[i + 16] = expandONe(i + 16, messageBlock, doublePipe, fullQuadruple);
        }
        for (int i = getExpandRoundsOne(); i < 16; i++) {
            fullQuadruple[i + 16] = expandTwo(i + 16, messageBlock, doublePipe, fullQuadruple);
        }
        return fullQuadruple;
    }

    private void fTwoFunction(long[] messageBlock, long[] quadruplePipe) {
        long xL = 0;
        for (int i = 16; i < 24; i++) {
            xL ^= quadruplePipe[i];
        }
        long xH = xL;
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
        currentDoublePipe[8] = Long.rotateLeft(currentDoublePipe[4], 9) + (xH ^ quadruplePipe[24] ^ messageBlock[8]) + ((xL << 8) ^ quadruplePipe[23] ^ quadruplePipe[8]);
        currentDoublePipe[9] = Long.rotateLeft(currentDoublePipe[5], 10) + (xH ^ quadruplePipe[25] ^ messageBlock[9]) + ((xL >>> 6) ^ quadruplePipe[16] ^ quadruplePipe[9]);
        currentDoublePipe[10] = Long.rotateLeft(currentDoublePipe[6], 11) + (xH ^ quadruplePipe[26] ^ messageBlock[10]) + ((xL << 6) ^ quadruplePipe[17] ^ quadruplePipe[10]);
        currentDoublePipe[11] = Long.rotateLeft(currentDoublePipe[7], 12) + (xH ^ quadruplePipe[27] ^ messageBlock[11]) + ((xL << 4) ^ quadruplePipe[18] ^ quadruplePipe[11]);
        currentDoublePipe[12] = Long.rotateLeft(currentDoublePipe[0], 13) + (xH ^ quadruplePipe[28] ^ messageBlock[12]) + ((xL >>> 3) ^ quadruplePipe[19] ^ quadruplePipe[12]);
        currentDoublePipe[13] = Long.rotateLeft(currentDoublePipe[1], 14) + (xH ^ quadruplePipe[29] ^ messageBlock[13]) + ((xL >>> 4) ^ quadruplePipe[20] ^ quadruplePipe[13]);
        currentDoublePipe[14] = Long.rotateLeft(currentDoublePipe[2], 15) + (xH ^ quadruplePipe[30] ^ messageBlock[14]) + ((xL >>> 7) ^ quadruplePipe[21] ^ quadruplePipe[14]);
        currentDoublePipe[15] = Long.rotateLeft(currentDoublePipe[3], 16) + (xH ^ quadruplePipe[31] ^ messageBlock[15]) + ((xL >>> 2) ^ quadruplePipe[22] ^ quadruplePipe[15]);
    }

    private long r1(long x) {
        return Long.rotateLeft(x, 5);
    }


    private long r2(long x) {
        return Long.rotateLeft(x, 11);
    }


    private long r3(long x) {
        return Long.rotateLeft(x, 27);
    }


    private long r4(long x) {
        return Long.rotateLeft(x, 32);
    }


    private long r5(long x) {
        return Long.rotateLeft(x, 37);
    }


    private long r6(long x) {
        return Long.rotateLeft(x, 43);
    }


    private long r7(long x) {
        return Long.rotateLeft(x, 53);
    }


    private long s0(long x) {
        return (x >>> 1) ^ (x << 3) ^ Long.rotateLeft(x, 4) ^ Long.rotateLeft(x, 37);
    }


    private long s1(long x) {
        return (x >>> 1) ^ (x << 2) ^ Long.rotateLeft(x, 13) ^ Long.rotateLeft(x, 43);
    }


    private long s2(long x) {
        return (x >>> 2) ^ (x << 1) ^ Long.rotateLeft(x, 19) ^ Long.rotateLeft(x, 53);
    }


    private long s3(long x) {
        return (x >>> 2) ^ (x << 2) ^ Long.rotateLeft(x, 28) ^ Long.rotateLeft(x, 59);
    }


    private long s4(long x) {
        return (x >>> 1) ^ x;
    }


    private long s5(long x) {
        return (x >>> 2) ^ x;
    }

    private long addElement(int j, long[] messageBlock, long[] doublePipe) {
        return (Long.rotateLeft(messageBlock[(j) % 16], (j + 1) % 16 == 0 ? 16 : (j + 1) % 16)
                + Long.rotateLeft(messageBlock[(j + 3) % 16], (j + 4) % 16 == 0 ? 16 : (j + 4) % 16)
                - Long.rotateLeft(messageBlock[(j + 10) % 16], (j + 11) % 16 == 0 ? 16 : (j + 11) % 16)
                + 0x0555555555555555L * (j + 16)) ^ doublePipe[(j + 7) % 16];
    }

    private long expandONe(int j, long[] messageBlock, long[] doublePipe, long[] quadruplePipe) {
        return s1(quadruplePipe[j - 16]) + s2(quadruplePipe[j - 15]) + s3(quadruplePipe[j - 14]) + s0(quadruplePipe[j - 13])
                + s1(quadruplePipe[j - 12]) + s2(quadruplePipe[j - 11]) + s3(quadruplePipe[j - 10]) + s0(quadruplePipe[j - 9])
                + s1(quadruplePipe[j - 8]) + s2(quadruplePipe[j - 7]) + s3(quadruplePipe[j - 6]) + s0(quadruplePipe[j - 5])
                + s1(quadruplePipe[j - 4]) + s2(quadruplePipe[j - 3]) + s3(quadruplePipe[j - 2]) + s0(quadruplePipe[j - 1])
                + addElement(j - 16, messageBlock, doublePipe);
    }

    private long expandTwo(int j, long[] messageBlock, long[] doublePipe, long[] quadruplePipe) {
        return quadruplePipe[j - 16] + r1(quadruplePipe[j - 15]) + quadruplePipe[j - 14] + r2(quadruplePipe[j - 13])
                + quadruplePipe[j - 12] + r3(quadruplePipe[j - 11]) + quadruplePipe[j - 10] + r4(quadruplePipe[j - 9])
                + quadruplePipe[j - 8] + r5(quadruplePipe[j - 7]) + quadruplePipe[j - 6] + r6(quadruplePipe[j - 5])
                + quadruplePipe[j - 4] + r7(quadruplePipe[j - 3]) + s4(quadruplePipe[j - 2]) + s5(quadruplePipe[j - 1])
                + addElement(j - 16, messageBlock, doublePipe);
    }
}
