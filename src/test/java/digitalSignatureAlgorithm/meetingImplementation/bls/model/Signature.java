package digitalSignatureAlgorithm.meetingImplementation.bls.model;

import digitalSignatureAlgorithm.it.unisa.dia.gas.jpbc.Element;

/**
 * Created by Ilya Gazman on 2/3/2018.
 */
public class Signature {
    public byte[] message;
    public Element publicKey;
    public Element signature;
}
