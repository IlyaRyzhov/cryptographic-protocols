package digitalSignatureAlgorithm.it.unisa.dia.gas.plaf.jpbc.util.concurrent.recursive;

import digitalSignatureAlgorithm.it.unisa.dia.gas.jpbc.Element;

import java.util.concurrent.RecursiveTask;

/**
 * @author Angelo De Caro (jpbclib@gmail.com)
 * @since 2.0.0
 */
class RecursiveMultiplier extends RecursiveTask<Element> {
    private static final int SEQUENTIAL_THRESHOLD = 2;

    private final Element[] elements;
    private final int low;
    private final int high;

    private RecursiveMultiplier(Element[] elements, int lo, int hi) {
        this.elements = elements;
        this.low = lo;
        this.high = hi;
    }

    protected Element compute() {
        if (high == low) {
            return elements[low];
        }

        if (high - low < SEQUENTIAL_THRESHOLD) {
            return elements[low].mul(elements[high]);
        } else {
            int mid = low + (high - low) / 2;

            RecursiveMultiplier left = new RecursiveMultiplier(elements, low, mid);
            RecursiveMultiplier right = new RecursiveMultiplier(elements, mid + 1, high);
            left.fork();

            Element rightAns = right.compute();
            Element leftAns = left.join();
            return rightAns.mul(leftAns);
        }
    }

}

