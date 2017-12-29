import java.util.Set;
import java.util.HashSet;
import java.security.PublicKey;
import java.util.ArrayList;
import java.util.Arrays;

public class TxHandler {

    UTXOPool utxoPool;

    /**
     * Creates a public ledger whose current UTXOPool (collection of unspent transaction outputs) is
     * {@code utxoPool}. This should make a copy of utxoPool by using the UTXOPool(UTXOPool uPool)
     * constructor.
     */
    public TxHandler(UTXOPool utxoPool) {
        this.utxoPool = new UTXOPool(utxoPool);
    }

    /**
     * @return true if:
     * (1) all outputs claimed by {@code tx} are in the current UTXO pool, 
     * (2) the signatures on each input of {@code tx} are valid, 
     * (3) no UTXO is claimed multiple times by {@code tx},
     * (4) all of {@code tx}s output values are non-negative, and
     * (5) the sum of {@code tx}s input values is greater than or equal to the sum of its output
     *     values; and false otherwise.
     */
    public boolean isValidTx(Transaction tx) {
        Set<UTXO> utxos = new HashSet<UTXO>();

        double total_output = 0;
        for (Transaction.Output output : tx.getOutputs()) {
            double val = output.value;
            if (val <= 0) {
                // (4) output values are non negative
                return false;
            }
            total_output += val;
        }

        double total_input = 0;
        int inputIndex = 0;
        for (Transaction.Input input : tx.getInputs()) {
            byte[] prevTxHash = input.prevTxHash;
            int outputIndex = input.outputIndex;
            UTXO utxo = new UTXO(prevTxHash, outputIndex);
            if (utxos.contains(utxo)) {
                // (3) all utxo are distincts
                return false;
            }
            utxos.add(utxo);
            Transaction.Output output = utxoPool.getTxOutput(utxo);
            if (output == null) {
                // (1) all outputs belong to the current UTXO pool
                return false;
            }

            byte[] signature = input.signature;
            PublicKey address = output.address;

            byte[] message = tx.getRawDataToSign(inputIndex); 
            inputIndex++;
            if (!Crypto.verifySignature(address, message, signature)) {
                return false; // (2)
            }

            total_input += output.value;
        }

        if (total_output > total_input) {
            return false; // (5)
        }

        return true;
    }

    /**
     * Handles each epoch by receiving an unordered array of proposed transactions, checking each
     * transaction for correctness, returning a mutually valid array of accepted transactions, and
     * updating the current UTXO pool as appropriate.
     */
    public Transaction[] handleTxs(Transaction[] possibleTxs) {

        ArrayList<Transaction> mutuallyValidTransactions = new ArrayList<Transaction>();

        boolean keepGoing = true;
       
        while (keepGoing) {

            keepGoing = false;

            for (Transaction candidate : possibleTxs) {
                // we pick every transaction and check if 
                // 1 - it is valid by itself
                // 2 - mutually valid with transactions picked until this point
                // 
                // If candidate transaction is selected, its output operations
                // are added to the current UTXO pool, and its input operations 
                // are removed from the UTXO pool. It is important to update the 
                // UTXO pool right after the transaction is selected because 
                // subsequent transactions my refer to it.

                if (!isValidTx(candidate)) {
                    continue;
                }
                keepGoing = true;

                mutuallyValidTransactions.add(candidate);

                for (Transaction.Input input : candidate.getInputs()) {
                    byte[] prevTxHash = input.prevTxHash;
                    int outputIndex = input.outputIndex;
                    UTXO utxo = new UTXO(prevTxHash, outputIndex);
                    utxoPool.removeUTXO(utxo);
                }

                for (int outputIndex = 0; outputIndex < candidate.numOutputs(); outputIndex++) {
                    Transaction.Output output = candidate.getOutput(outputIndex);
                    UTXO utxo = new UTXO(candidate.getHash(), outputIndex);
                    utxoPool.addUTXO(utxo, output);
                }
            }

        }

        Transaction[] res = new Transaction[mutuallyValidTransactions.size()];
        return mutuallyValidTransactions.toArray(res);
    }

}
