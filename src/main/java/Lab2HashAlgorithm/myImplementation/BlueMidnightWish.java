package Lab2HashAlgorithm.myImplementation;

import static Lab2HashAlgorithm.myImplementation.BlueMidnightWishDigestSize.BLUE_MIDNIGHT_WISH_224;
import static Lab2HashAlgorithm.myImplementation.BlueMidnightWishDigestSize.BLUE_MIDNIGHT_WISH_256;

public class BlueMidnightWish implements HashFunction {
    private BlueMidnightWishAbstract blueMidnightWishImplementation;

    public BlueMidnightWish(BlueMidnightWishDigestSize blueMidnightWishDigestSize) {
        setOutputSize(blueMidnightWishDigestSize);
    }

    @Override
    public byte[] computeHash(byte[] message) {
        return blueMidnightWishImplementation.computeHash(message);
    }

    public void setOutputSize(BlueMidnightWishDigestSize blueMidnightWishDigestSize) {
        if (blueMidnightWishDigestSize == BLUE_MIDNIGHT_WISH_224 || blueMidnightWishDigestSize == BLUE_MIDNIGHT_WISH_256) {
            blueMidnightWishImplementation = new BlueMidnightWishWithIntegerWord(blueMidnightWishDigestSize);
        } else blueMidnightWishImplementation = new BlueMidnightWishWithLongWord(blueMidnightWishDigestSize);
    }

    @Override
    public int getBlockSize() {
        return blueMidnightWishImplementation.getBlockSize();
    }

    @Override
    public int getOutputLength() {
        return blueMidnightWishImplementation.getOutputLength();
    }
}
