package Lab4EncryptionModes;

import java.io.File;

public interface EncryptionAlgorithmWithMode {
    byte[] encryptMessage(byte[] plainMessage);

    byte[] decryptMessage(byte[] encryptedMessage);

    void encryptFile(File fileToEncrypt, String pathForEncryptedFile);

    void decryptFile(File fileToDecrypt, String pathForDecryptedFile);
}
