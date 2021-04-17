package Lab1EncryptionAlgorithm;

public interface EncryptionAlgorithm {
    byte[] encryptOneBlock(byte[] plainText);

    byte[] decryptOneBlock(byte[] cipherText);

    int getBlockSizeInBytes();
}
