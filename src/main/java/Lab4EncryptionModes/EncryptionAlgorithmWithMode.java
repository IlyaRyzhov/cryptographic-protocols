package Lab4EncryptionModes;

import java.io.File;

public interface EncryptionAlgorithmWithMode {
    byte[] encryptMessage(byte[] plainText);

    byte[] decryptMessage(byte[] cipherText);

    void encryptFile(File fileToEncrypt, String pathForEncryptedFile);

    void decryptFile(File fileToDecrypt, String pathForDecryptedFile);
}
