package Lab1EncryptionAlgorithm;

public interface EncryptionAlgorithm {
    byte[] encryptOneBlock(byte[] plainText);

    byte[] decryptOneBlock(byte[] cipherText);

    int getBlockSizeInBytes();

    int getKeySizeInBytes();

    void setKey(long[] key);

    EncryptionAlgorithm getInstance();
}
