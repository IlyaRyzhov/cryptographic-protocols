package Lab2HashAlgorithm;

import static Lab2HashAlgorithm.BlueMidnightWishDigestSize.*;

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

    public BlueMidnightWishAbstract getBlueMidnightWishImplementation() {
        return blueMidnightWishImplementation;
    }
}
