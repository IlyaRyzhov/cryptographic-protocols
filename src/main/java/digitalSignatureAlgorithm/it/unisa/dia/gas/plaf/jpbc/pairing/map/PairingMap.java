package digitalSignatureAlgorithm.it.unisa.dia.gas.plaf.jpbc.pairing.map;

import digitalSignatureAlgorithm.it.unisa.dia.gas.jpbc.Element;
import digitalSignatureAlgorithm.it.unisa.dia.gas.jpbc.PairingPreProcessing;
import digitalSignatureAlgorithm.it.unisa.dia.gas.jpbc.Point;

/**
 * @author Angelo De Caro (jpbclib@gmail.com)
 */
public interface PairingMap {

    Element pairing(Point in1, Point in2);

    boolean isProductPairingSupported();

    Element pairing(Element[] in1, Element[] in2);


    void finalPow(Element element);


    int getPairingPreProcessingLengthInBytes();

    PairingPreProcessing pairing(Point in1);

    PairingPreProcessing pairing(byte[] source, int offset);


}
