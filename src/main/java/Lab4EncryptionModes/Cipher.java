package Lab4EncryptionModes;

import Lab1EncryptionAlgorithm.EncryptionAlgorithm;
import Lab1EncryptionAlgorithm.TwoFish;

import java.io.File;

import static Lab4EncryptionModes.EncryptionMode.*;

public class Cipher implements EncryptionAlgorithmWithMode {
    private EncryptionMode encryptionMode;
    private EncryptionAlgorithmAbstract encryptionAlgorithmWithMode;

    public Cipher(EncryptionAlgorithm encryptionAlgorithm, EncryptionMode encryptionMode) {
        this.encryptionMode = encryptionMode;
        switch (encryptionMode) {
            case ECB:
                encryptionAlgorithmWithMode = new EncryptionAlgorithmWithECB(encryptionAlgorithm);
                break;
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

    public static void main(String[] args) {
        EncryptionAlgorithm encryptionAlgorithm = new TwoFish(new long[]{0, 0});
        Cipher cipher = new Cipher(encryptionAlgorithm, ECB);
        byte[] ct = cipher.encryptMessage(new byte[16]);
        for (int i = 0; i < ct.length; i++) {
            System.out.print(Integer.toHexString(ct[i] & 0xff));
        }
    }
}
