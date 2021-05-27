package Lab3DigitalSignatureAlgorithm.it.unisa.dia.gas.plaf.jpbc.pairing.accumulator;

import Lab3DigitalSignatureAlgorithm.it.unisa.dia.gas.jpbc.Element;
import Lab3DigitalSignatureAlgorithm.it.unisa.dia.gas.plaf.jpbc.util.concurrent.accumultor.Accumulator;

/**
 * @author Angelo De Caro (jpbclib@gmail.com)
 * @since 2.0.0
 */
public interface PairingAccumulator extends Accumulator<Element> {

    void addPairing(Element e1, Element e2);

}
