package digitalSignatureAlgorithm.it.unisa.dia.gas.plaf.jpbc.pairing.accumulator;

import digitalSignatureAlgorithm.it.unisa.dia.gas.jpbc.Element;
import digitalSignatureAlgorithm.it.unisa.dia.gas.jpbc.Pairing;

/**
 * @author Angelo De Caro (jpbclib@gmail.com)
 * @since 2.0.0
 */
public class MultiThreadedMulPairingAccumulator extends AbstractPairingAccumulator {


    public MultiThreadedMulPairingAccumulator(Pairing pairing) {
        super(pairing);
    }


    protected void reduce(Element value) {
        this.result.mul(value);
    }
}
