package Lab7MutualAuthenticationProtocol;

import Lab5RandomNumberGenerator.RandomNumberGenerator;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.util.*;

import static Lab7MutualAuthenticationProtocol.UserRole.INITIATOR;
import static Utils.CommonUtils.concatenateByteArrays;
import static Utils.EncryptionModesUtils.xorByteArrays;
import static Utils.TransmissionChannelUtils.readMessageFromTransmissionChannel;
import static Utils.TransmissionChannelUtils.writeMessageToTransmissionChannel;
import static Lab7MutualAuthenticationProtocol.SecureRemotePasswordProtocol.*;

public class UserOfProtocolWithoutTrustedServer extends UserOfTransmissionProtocol {
    private byte[] userSecretKey;
    private final Map<String, List<byte[]>> namePasswordVerifierMap;
    private final Set<String> pretenderNames;
    private BigInteger initiatorIdentifier;
    private BigInteger pretenderIdentifier;
    private byte[] randomIdentifier;

    public UserOfProtocolWithoutTrustedServer(String name, byte[] userKey, UserRole userRole) {
        super(name, userKey, userRole);
        namePasswordVerifierMap = new LinkedHashMap<>();
        pretenderNames = new LinkedHashSet<>();
    }

    @Override
    public void authenticatePretender(UserOfTransmissionProtocol pretender) {
        if (userRole == INITIATOR) {
            SecureRemotePasswordProtocol secureRemotePasswordProtocol = new SecureRemotePasswordProtocol();
            while (true) {
                boolean authenticationResult = secureRemotePasswordProtocol.authenticateTwoUsers(this, pretender);
                if (authenticationResult)
                    break;
            }
        }
    }

    public void sendUserName() {
        writeMessageToTransmissionChannel(name.getBytes(StandardCharsets.UTF_8));
    }

    public void sendSalt() {
        byte[] salt = new RandomNumberGenerator().generateRandomBytes(64);
        userSecretKey = getUserSecretKey(salt, userKey);
        writeMessageToTransmissionChannel(salt);
    }

    public void sendPasswordVerifier() {
        BigInteger passwordVerifier = generatingElement.modPow(new BigInteger(1, userSecretKey).mod(groupModule), groupModule);
        writeMessageToTransmissionChannel(passwordVerifier.toByteArray());
    }

    public void addSaltFromChannel(String senderName) {
        byte[] salt = readMessageFromTransmissionChannel();
        namePasswordVerifierMap.computeIfAbsent(senderName, k -> new ArrayList<>());
        namePasswordVerifierMap.get(senderName).add(salt);
    }

    public void addUserNameFromChannel() {
        namePasswordVerifierMap.put(new String(readMessageFromTransmissionChannel(), StandardCharsets.UTF_8), null);
    }

    public void addPasswordVerifierFromChannel(String senderName) {
        namePasswordVerifierMap.get(senderName).add(readMessageFromTransmissionChannel());
    }

    public void sendInitiatorIdentifier() {
        writeMessageToTransmissionChannel(initiatorIdentifier.toByteArray());
    }

    public void sendPretenderIdentifier() {
        writeMessageToTransmissionChannel(pretenderIdentifier.toByteArray());
    }

    public void getSessionKeyForInitiator(byte[] salt, byte[] password) {
        BigInteger uParameter = new BigInteger(1, hashFunction.computeHash(concatenateByteArrays(initiatorIdentifier.toByteArray(), pretenderIdentifier.toByteArray()))).mod(groupModule);
        BigInteger userSecretKey = new BigInteger(1, getUserSecretKey(salt, password)).mod(groupModule);
        BigInteger degree = ((new BigInteger(1, randomIdentifier).mod(groupModule)).add(uParameter.multiply(userSecretKey).mod(groupModule))).mod(groupModule);
        BigInteger generatingElementPowSecretKey = generatingElement.modPow(userSecretKey, groupModule);
        BigInteger sParameter = ((pretenderIdentifier.subtract(kParameter.multiply(generatingElementPowSecretKey).mod(groupModule))).mod(groupModule)).modPow(degree, groupModule);
        sessionKey = hashFunction.computeHash(sParameter.toByteArray());
    }

    public void getSessionKeyForPretender(String initiatorName) {
        BigInteger uParameter = new BigInteger(1, hashFunction.computeHash(concatenateByteArrays(initiatorIdentifier.toByteArray(), pretenderIdentifier.toByteArray()))).mod(groupModule);
        BigInteger initiatorPasswordVerifier = new BigInteger(1, namePasswordVerifierMap.get(initiatorName).get(1)).mod(groupModule);
        BigInteger degree = new BigInteger(1, randomIdentifier).mod(groupModule);
        BigInteger sParameter = (initiatorIdentifier.multiply(initiatorPasswordVerifier.modPow(uParameter, groupModule)).mod(groupModule)).modPow(degree, groupModule);
        sessionKey = hashFunction.computeHash(sParameter.toByteArray());
    }

    public byte[] getInitiatorKeyCheckMessage(byte[] salt, String initiatorName) {
        byte[] initiatorKeyCheckMessage = hashFunction.computeHash(groupModule.toByteArray());
        xorByteArrays(initiatorKeyCheckMessage, hashFunction.computeHash(generatingElement.toByteArray()), initiatorKeyCheckMessage.length);
        initiatorKeyCheckMessage = concatenateByteArrays(initiatorKeyCheckMessage, hashFunction.computeHash(initiatorName.getBytes(StandardCharsets.UTF_8)));
        initiatorKeyCheckMessage = concatenateByteArrays(initiatorKeyCheckMessage, salt);
        initiatorKeyCheckMessage = concatenateByteArrays(initiatorKeyCheckMessage, initiatorIdentifier.toByteArray());
        initiatorKeyCheckMessage = concatenateByteArrays(initiatorKeyCheckMessage, pretenderIdentifier.toByteArray());
        initiatorKeyCheckMessage = concatenateByteArrays(initiatorKeyCheckMessage, sessionKey);
        return hashFunction.computeHash(initiatorKeyCheckMessage);
    }

    public byte[] getPretenderKeyCheckMessage(byte[] initiatorKeyCheckMessage) {
        return hashFunction.computeHash(concatenateByteArrays(concatenateByteArrays(initiatorIdentifier.toByteArray(), initiatorKeyCheckMessage), sessionKey));
    }

    private byte[] getUserSecretKey(byte[] salt, byte[] password) {
        return hashFunction.computeHash(concatenateByteArrays(salt, password));
    }

    public Map<String, List<byte[]>> getNamePasswordVerifierMap() {
        return namePasswordVerifierMap;
    }

    public Set<String> getPretenderNames() {
        return pretenderNames;
    }

    public byte[] getRandomIdentifier() {
        return randomIdentifier;
    }

    public void setRandomIdentifier(byte[] randomIdentifier) {
        this.randomIdentifier = randomIdentifier;
    }

    public void setInitiatorIdentifier(BigInteger initiatorIdentifier) {
        this.initiatorIdentifier = initiatorIdentifier;
    }

    public void setPretenderIdentifier(BigInteger pretenderIdentifier) {
        this.pretenderIdentifier = pretenderIdentifier;
    }
}
