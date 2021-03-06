package digitalSignatureAlgorithm.it.unisa.dia.gas.plaf.jpbc.field.base;

import digitalSignatureAlgorithm.it.unisa.dia.gas.jpbc.Element;
import digitalSignatureAlgorithm.it.unisa.dia.gas.jpbc.Field;
import digitalSignatureAlgorithm.it.unisa.dia.gas.jpbc.FieldOver;

/**
 * @author Angelo De Caro (jpbclib@gmail.com)
 */
public abstract class AbstractFieldOver<F extends Field, E extends Element> extends AbstractField<E> implements FieldOver<F, E> {
    protected final F targetField;

    protected AbstractFieldOver(F targetField) {
        this.targetField = targetField;
    }


    public F getTargetField() {
        return targetField;
    }

}
