package hashAlgorithm;

public enum BlueMidnightWishDigestSize {
    BLUE_MIDNIGHT_WISH_224("BMW 224"),
    BLUE_MIDNIGHT_WISH_256("BMW 256"),
    BLUE_MIDNIGHT_WISH_384("BMW 384"),
    BLUE_MIDNIGHT_WISH_512("BMW 512");
    private final String algorithmName;

    BlueMidnightWishDigestSize(String algorithmName) {
        this.algorithmName = algorithmName;
    }

    public String getAlgorithmName() {
        return algorithmName;
    }

}
