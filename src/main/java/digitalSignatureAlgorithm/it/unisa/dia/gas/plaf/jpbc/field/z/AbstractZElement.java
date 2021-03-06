package digitalSignatureAlgorithm.it.unisa.dia.gas.plaf.jpbc.field.z;

import digitalSignatureAlgorithm.it.unisa.dia.gas.plaf.jpbc.field.base.AbstractElement;
import digitalSignatureAlgorithm.it.unisa.dia.gas.plaf.jpbc.field.base.AbstractField;

import java.math.BigInteger;

/**
 * @author Angelo De Caro (jpbclib@gmail.com)
 */
abstract class AbstractZElement<F extends AbstractField> extends AbstractElement<F> {

    BigInteger value;

    AbstractZElement(F field) {
        super(field);
    }
}
