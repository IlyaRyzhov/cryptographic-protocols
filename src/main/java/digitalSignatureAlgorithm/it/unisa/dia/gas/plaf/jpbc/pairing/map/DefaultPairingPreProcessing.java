package digitalSignatureAlgorithm.it.unisa.dia.gas.plaf.jpbc.pairing.map;

import digitalSignatureAlgorithm.it.unisa.dia.gas.jpbc.Element;
import digitalSignatureAlgorithm.it.unisa.dia.gas.jpbc.Field;
import digitalSignatureAlgorithm.it.unisa.dia.gas.jpbc.Pairing;
import digitalSignatureAlgorithm.it.unisa.dia.gas.jpbc.PairingPreProcessing;

/**
 * @author Angelo De Caro (jpbclib@gmail.com)
 * @since 2.0.0
 */
public class DefaultPairingPreProcessing implements PairingPreProcessing {

    private final Pairing pairing;
    private final Element in1;

    public DefaultPairingPreProcessing(Pairing pairing, Element in1) {
        this.pairing = pairing;
        this.in1 = in1;
    }

    public DefaultPairingPreProcessing(Pairing pairing, Field field, byte[] source, int offset) {
        this.pairing = pairing;
        this.in1 = field.newElementFromBytes(source, offset);
    }

    public Element pairing(Element in2) {
        return pairing.pairing(in1, in2);
    }

}
