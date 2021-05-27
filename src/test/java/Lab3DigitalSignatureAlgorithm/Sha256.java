package Lab3DigitalSignatureAlgorithm;

import Lab2HashAlgorithm.HashFunction;

import java.io.File;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

public class Sha256 implements HashFunction {
    @Override
    public byte[] computeHash(byte[] message) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            return digest.digest(message);
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
        return null;
    }

    @Override
    public byte[] computeHashOfFile(File file) {
        return new byte[0];
    }

    @Override
    public int getBlockSize() {
        return 64;
    }

    @Override
    public int getOutputLength() {
        return 32;
    }
}

