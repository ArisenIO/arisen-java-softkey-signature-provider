package one.block.arisensoftkeysignatureprovider;


import one.block.arisenjava.enums.AlgorithmEmployed;
import one.block.arisenjava.error.ArisenError;
import one.block.arisenjava.error.signatureProvider.GetAvailableKeysError;
import one.block.arisenjava.error.signatureProvider.SignTransactionError;
import one.block.arisenjava.error.utilities.RIXFormatterError;
import one.block.arisenjava.error.utilities.RIXFormatterSignatureIsNotCanonicalError;
import one.block.arisenjava.error.utilities.PEMProcessorError;
import one.block.arisenjava.interfaces.ISignatureProvider;
import one.block.arisenjava.models.signatureProvider.ArisenTransactionSignatureRequest;
import one.block.arisenjava.models.signatureProvider.ArisenTransactionSignatureResponse;
import one.block.arisenjava.utilities.RIXFormatter;
import one.block.arisenjava.utilities.PEMProcessor;
import one.block.arisensoftkeysignatureprovider.error.ImportKeyError;
import one.block.arisensoftkeysignatureprovider.error.SoftKeySignatureErrorConstants;
import org.bitcoinj.core.Sha256Hash;
import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.crypto.params.ECPrivateKeyParameters;
import org.bouncycastle.crypto.signers.ECDSASigner;
import org.bouncycastle.util.encoders.Hex;
import org.jetbrains.annotations.NotNull;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;

/**
 * Example signature provider implementation for arisen-java SDK that signs transactions using
 * an in-memory private key generated with the secp256r1, prime256v1, or secp256k1 algorithms.  This
 * implementation is NOT secure and should only be used for educational purposes.  It is NOT
 * advisable to store private keys outside of secure devices like TEE's and SE's.
 */
public class SoftKeySignatureProviderImpl implements ISignatureProvider {

    /**
     * Keep a Set (Unique) of private keys in PEM format
     */
    private Set<String> keys = new LinkedHashSet<>();

    /**
     * Maximum number of times the signature provider should try to create a canonical signature
     * for a secp256k1 generated key when the attempt fails.
     */
    private static final int MAX_NOT_CANONICAL_RE_SIGN = 100;

    /**
     * Index of R value in the signature result of softkey signing
     */
    private static final int R_INDEX = 0;

    /**
     * Index of S value in the signature result of softkey signing
     */
    private static final int S_INDEX = 1;

    /**
     * Signum to convert a negative value to a positive Big Integer
     */
    private static final int BIG_INTEGER_POSITIVE = 1;

    /**
     * Flag to indicate getAvailableKeys() should return keys generated with the secp256k1 algorithm in the legacy (prefaced with "RIX")
     */
    private static final boolean USING_K1_LEGACY_FORMAT = true;

    /**
     * Flag to indicate getAvailableKeys() should return keys generated with the secp256k1 algorithm in the new (prefaced with "PUB_K1_") formats
     */
    private static final boolean USING_K1_NON_LEGACY_FORMAT = false;

    /**
     * Flag to indicate whether getAvailableKeys() should return keys generated with the secp256k1 algorithm in the legacy (prefaced with "RIX") or new (prefaced with "PUB_K1_") formats.
     */
    private static final boolean DEFAULT_WHETHER_USING_K1_LEGACY_FORMAT = USING_K1_NON_LEGACY_FORMAT;

    /**
     * Import private key into softkey signature provider.  Private key is stored in memory.
     * NOT RECOMMENDED for production use!!!!
     *
     * @param privateKey - RIX format private key
     * @throws ImportKeyError Exception that occurs while trying to import a key
     */
    public void importKey(@NotNull String privateKey) throws ImportKeyError {
        if (privateKey.isEmpty()) {
            throw new ImportKeyError(SoftKeySignatureErrorConstants.IMPORT_KEY_INPUT_EMPTY_ERROR);
        }

        String privateKeyPem;

        try {
            privateKeyPem = RIXFormatter.convertRIXPrivateKeyToPEMFormat(privateKey);
        } catch (RIXFormatterError RIXFormatterError) {
            throw new ImportKeyError(String.format(SoftKeySignatureErrorConstants.IMPORT_KEY_CONVERT_TO_PEM_ERROR, privateKey), RIXFormatterError);
        }

        if (privateKeyPem.isEmpty()) {
            throw new ImportKeyError(SoftKeySignatureErrorConstants.CONVERT_TO_PEM_EMPTY_ERROR);
        }

        this.keys.add(privateKeyPem);
    }

    @Override
    public @NotNull ArisenTransactionSignatureResponse signTransaction(@NotNull ArisenTransactionSignatureRequest arisenTransactionSignatureRequest) throws SignTransactionError {

        if (arisenTransactionSignatureRequest.getSigningPublicKeys().isEmpty()) {
            throw new SignTransactionError(SoftKeySignatureErrorConstants.SIGN_TRANS_EMPTY_KEY_LIST);

        }

        if (arisenTransactionSignatureRequest.getChainId().isEmpty()) {
            throw new SignTransactionError(SoftKeySignatureErrorConstants.SIGN_TRANS_EMPTY_CHAIN_ID);
        }

        if (arisenTransactionSignatureRequest.getSerializedTransaction().isEmpty()) {
            throw new SignTransactionError(SoftKeySignatureErrorConstants.SIGN_TRANS_EMPTY_TRANSACTION);
        }

        // Getting serializedTransaction and preparing signable transaction
        String serializedTransaction = arisenTransactionSignatureRequest.getSerializedTransaction();

        // This is the un-hashed message which is used to recover public key
        byte[] message;

        // This is the hashed message which is signed.
        byte[] hashedMessage;

        try {
            message = Hex.decode(RIXFormatter.prepareSerializedTransactionForSigning(serializedTransaction, arisenTransactionSignatureRequest.getChainId()).toUpperCase());
            hashedMessage = Sha256Hash.hash(message);
        } catch (RIXFormatterError rFormatterError) {
            throw new SignTransactionError(String.format(SoftKeySignatureErrorConstants.SIGN_TRANS_PREPARE_SIGNABLE_TRANS_ERROR, serializedTransaction), RIXFormatterError);
        }

        if (this.keys.isEmpty()) {
            throw new SignTransactionError(SoftKeySignatureErrorConstants.SIGN_TRANS_NO_KEY_AVAILABLE);
        }

        List<String> signatures = new ArrayList<>();

        // Getting public key and search for the corresponding private key
        for (String inputPublicKey : arisenTransactionSignatureRequest.getSigningPublicKeys()) {

            BigInteger privateKeyBI = BigInteger.ZERO;
            AlgorithmEmployed curve = null;

            try {
                // Search for corresponding private key
                for (String key : keys) {
                    PEMProcessor availableKeyProcessor = new PEMProcessor(key);
                    //Extract public key in PEM format from inner private key
                    String innerPublicKeyPEM = availableKeyProcessor.extractPEMPublicKeyFromPrivateKey(DEFAULT_WHETHER_USING_K1_LEGACY_FORMAT);

                    // Convert input public key to PEM format for comparision
                    String inputPublicKeyPEM = RIXFormatter.convertRIXPublicKeyToPEMFormat(inputPublicKey);

                    if (innerPublicKeyPEM.equals(inputPublicKeyPEM)) {
                        privateKeyBI = new BigInteger(BIG_INTEGER_POSITIVE, availableKeyProcessor.getKeyData());
                        curve = availableKeyProcessor.getAlgorithm();
                        break;
                    }
                }
            } catch (ArisenError error) {
                throw new SignTransactionError(String.format(SoftKeySignatureErrorConstants.SIGN_TRANS_SEARCH_KEY_ERROR, inputPublicKey), error);
            }

            // Throw error if found no private key with input public key
            //noinspection ConstantConditions
            if (privateKeyBI.equals(BigInteger.ZERO) || curve == null) {
                throw new SignTransactionError(String.format(SoftKeySignatureErrorConstants.SIGN_TRANS_KEY_NOT_FOUND, inputPublicKey));
            }

            for (int i = 0; i < MAX_NOT_CANONICAL_RE_SIGN; i++) {
                // Sign transaction
                // Use default constructor to have signature generated with secureRandom, otherwise it would generate same signature for same key all the time
                ECDSASigner signer = new ECDSASigner();

                ECDomainParameters domainParameters;
                try {
                    domainParameters = PEMProcessor.getCurveDomainParameters(curve);
                } catch (PEMProcessorError processorError) {
                    throw new SignTransactionError(String.format(SoftKeySignatureErrorConstants.SIGN_TRANS_GET_CURVE_DOMAIN_ERROR, curve.getString()), processorError);
                }

                ECPrivateKeyParameters parameters = new ECPrivateKeyParameters(privateKeyBI, domainParameters);
                signer.init(true, parameters);
                BigInteger[] signatureComponents = signer.generateSignature(hashedMessage);

                try {
                    String signature = RIXFormatter.convertRawRandSofSignatureToRIXFormat(signatureComponents[R_INDEX].toString(), signatureComponents[S_INDEX].toString(), message, RIXFormatter.convertRIXPublicKeyToPEMFormat(inputPublicKey));
                    // Format Signature
                    signatures.add(signature);
                    break;
                } catch (RIXFormatterError RIXFormatterError) {
                    // In theory, Non-canonical error only happened with K1 key
                    if (RIXFormatterError.getCause() instanceof RIXFormatterSignatureIsNotCanonicalError && curve == AlgorithmEmployed.SECP256K1) {
                        // Try to sign again until MAX_NOT_CANONICAL_RE_SIGN is reached or get a canonical signature
                        continue;
                    }

                    throw new SignTransactionError(SoftKeySignatureErrorConstants.SIGN_TRANS_FORMAT_SIGNATURE_ERROR, RIXFormatterError);
                }
            }
        }

        return new ArisenTransactionSignatureResponse(serializedTransaction, signatures, null);
    }

    /**
     * Gets available keys from signature provider <br> Check createSignatureRequest() flow in
     * "complete workflow" for more detail of how the method is used.
     * <p>
     * Public key of SECP256K1 has 2 types of format in Arisen which are "RIX" and "PUB_K1_" so this method return 2 public keys in both format for SECP256K1 and 1 public key for SECP256R1.
     *
     * @return the available keys of signature provider in RIX format
     * @throws GetAvailableKeysError thrown if there are any exceptions during the get available keys process.
     */
    @Override
    public @NotNull List<String> getAvailableKeys() throws GetAvailableKeysError {
        List<String> availableKeys = new ArrayList<>();
        if (this.keys.isEmpty()) {
            return availableKeys;
        }

        try {
            for (String key : this.keys) {
                PEMProcessor processor = new PEMProcessor(key);
                AlgorithmEmployed curve = processor.getAlgorithm();

                switch (curve) {
                    case SECP256R1:
                        // USING_K1_NON_LEGACY_FORMAT is being used here because its value does not matter to SECP256R1 key
                        availableKeys.add(processor.extractRIXPublicKeyFromPrivateKey(USING_K1_NON_LEGACY_FORMAT));
                        break;

                    case SECP256K1:
                        // Non legacy
                        availableKeys.add(processor.extractRIXPublicKeyFromPrivateKey(USING_K1_NON_LEGACY_FORMAT));
                        // legacy
                        availableKeys.add(processor.extractRIXPublicKeyFromPrivateKey(USING_K1_LEGACY_FORMAT));
                        break;

                    default:
                        throw new GetAvailableKeysError(SoftKeySignatureErrorConstants.GET_KEYS_KEY_FORMAT_NOT_SUPPORTED);
                }
            }
        } catch (PEMProcessorError pemProcessorError) {
            throw new GetAvailableKeysError(SoftKeySignatureErrorConstants.CONVERT_TO_PEM_EMPTY_ERROR, pemProcessorError);
        }

        return availableKeys;
    }
}
