package Lab2HashAlgorithm;

public abstract class BlueMidnightWishAbstract {
    //  private T[] initialDoublePipe;
    private final BlueFishDigestSize digestSize;

    protected abstract byte[] padMessage(byte[] message);

    protected abstract int solvePaddingEquation(long lengthOfMessage);

    protected BlueMidnightWishAbstract(BlueFishDigestSize digestSize) {
        this.digestSize = digestSize;
    }

   /* protected T[] getInitialDoublePipe() {
        return initialDoublePipe;
    }*/

 /*   protected void setInitialDoublePipe(T[] initialDoublePipe) {
        this.initialDoublePipe = initialDoublePipe;
    }*/

    protected BlueFishDigestSize getDigestSize() {
        return digestSize;
    }

   /* protected abstract T r1(T x);

    protected abstract T r2(T x);

    protected abstract T r3(T x);

    protected abstract T r4(T x);

    protected abstract T r5(T x);

    protected abstract T r6(T x);

    protected abstract T r7(T x);

    protected abstract T s0(T x);

    protected abstract T s1(T x);

    protected abstract T s2(T x);

    protected abstract T s3(T x);

    protected abstract T s4(T x);

    protected abstract T s5(T x);*/



   /* protected abstract int expandOne(int j);
    protected abstract int expandTwo(int j);
    protected abstract int addElement(int j);*/


 /*   T[] fZeroFunction(T[] messageBlock, T[] doublePipe) {

        T W0 = (messageBlock[5] ^ doublePipe[5]) - (messageBlock[7] ^ doublePipe[7]) + (messageBlock[10] ^ doublePipe[10]) + (messageBlock[13] ^ doublePipe[13]) + (messageBlock[14] ^ doublePipe[14]);
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
    }*/
}
