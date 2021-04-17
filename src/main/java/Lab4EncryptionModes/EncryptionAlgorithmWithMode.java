package Lab4EncryptionModes;

import java.io.File;

public interface EncryptionAlgorithmWithMode {
    //TODO дописать 2 метода с сигнатурой byte[],int, где int- длина IV в байтах, подумать над  использованием классов в cipher
    byte[] encryptMessage(byte[] plainText);

    byte[] decryptMessage(byte[] cipherText);

    void encryptFile(File fileToEncrypt, String pathForEncryptedFile);

    void decryptFile(File fileToDecrypt, String pathForDecryptedFile);
}
