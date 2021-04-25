package Lab4EncryptionModes;

import Lab1EncryptionAlgorithm.EncryptionAlgorithm;

import java.io.File;

public class Cipher implements EncryptionAlgorithmWithMode {
    private final EncryptionMode encryptionMode;
    private EncryptionAlgorithmAbstract encryptionAlgorithmWithMode;

    public Cipher(EncryptionAlgorithm encryptionAlgorithm, EncryptionMode encryptionMode, int... encryptionModeParameters) {
        this.encryptionMode = encryptionMode;
        switch (encryptionMode) {
            case ECB:
                encryptionAlgorithmWithMode = new EncryptionAlgorithmWithECB(encryptionAlgorithm);
                break;
            case CBC:
                encryptionAlgorithmWithMode = new EncryptionAlgorithmWithCBC(encryptionAlgorithm, encryptionModeParameters[0]);
                break;
            case CTR_ACPKM:
                encryptionAlgorithmWithMode = new EncryptionAlgorithmWithCTRACPKM(encryptionAlgorithm, encryptionModeParameters[0], encryptionModeParameters[1]);
            case MGM:
                encryptionAlgorithmWithMode = new EncryptionAlgorithmWithMGM(encryptionAlgorithm, encryptionModeParameters[0], encryptionModeParameters[1]);
            case OFB:
                encryptionAlgorithmWithMode = new EncryptionAlgorithmWithOFB(encryptionAlgorithm, encryptionModeParameters[0], encryptionModeParameters[1]);
        }
    }

    @Override
    public byte[] encryptMessage(byte[] plainText) {
        return encryptionAlgorithmWithMode.encryptMessage(plainText);
    }

    @Override
    public byte[] decryptMessage(byte[] cipherText) {
        return encryptionAlgorithmWithMode.decryptMessage(cipherText);
    }

    @Override
    public void encryptFile(File fileToEncrypt, String pathForEncryptedFile) {
        encryptionAlgorithmWithMode.encryptFile(fileToEncrypt, pathForEncryptedFile);
    }

    @Override
    public void decryptFile(File fileToDecrypt, String pathForDecryptedFile) {
        encryptionAlgorithmWithMode.decryptFile(fileToDecrypt, pathForDecryptedFile);
    }

    public void setBufferSize(int bufferSize) {
        encryptionAlgorithmWithMode.setBufferSize(bufferSize);
    }

    public EncryptionMode getEncryptionMode() {
        return encryptionMode;
    }
}
