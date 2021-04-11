package Lab2HashAlgorithm.myImplementation;

public interface HashFunction {
    byte[] computeHash(byte[] message);

    int getBlockSize();

    int getOutputLength();
}
