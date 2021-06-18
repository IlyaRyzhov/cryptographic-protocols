package mutualAuthenticationProtocol;

import hashAlgorithm.BlueMidnightWish;
import hashAlgorithm.BlueMidnightWishDigestSize;
import hashAlgorithm.HashFunction;
import randomNumberGenerator.RandomNumberGenerator;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.List;

import static Utils.CommonUtils.concatenateByteArrays;
import static Utils.TransmissionChannelUtils.readMessageFromTransmissionChannel;
import static Utils.TransmissionChannelUtils.writeMessageToTransmissionChannel;

public class SecureRemotePasswordProtocol extends AuthenticationProtocolAbstract {

    public static final BigInteger generatingElement;
    public static final BigInteger groupModule;
    public static final BigInteger kParameter;
    public static HashFunction hashFunction;

    static {
        BigInteger germainPrime = (new BigInteger("39051").multiply(new BigInteger("2").pow(6001))).subtract(BigInteger.ONE);//39051*2^(6001)- 1
        groupModule = (germainPrime.multiply(new BigInteger("2"))).add(BigInteger.ONE);
        generatingElement = groupModule.divide(new BigInteger("2"));
        hashFunction = new BlueMidnightWish(BlueMidnightWishDigestSize.BLUE_MIDNIGHT_WISH_512);
        byte[] moduleBytes = groupModule.toByteArray();
        byte[] generatingElementBytes = generatingElement.toByteArray();
        kParameter = new BigInteger(hashFunction.computeHash(concatenateByteArrays(moduleBytes, generatingElementBytes))).mod(groupModule);
    }

    /**
     * @see AuthenticationProtocolAbstract
     */
    @Override
    public boolean authenticateTwoUsers(UserOfTransmissionProtocol initiator, UserOfTransmissionProtocol pretender) {
        return authenticateTwoUsersWithoutTrustedServer((UserOfSecureRemotePasswordProtocol) initiator, (UserOfSecureRemotePasswordProtocol) pretender);
    }

    private boolean authenticateTwoUsersWithoutTrustedServer(UserOfSecureRemotePasswordProtocol initiator, UserOfSecureRemotePasswordProtocol pretender) {
        if (numberOfUnsuccessfulAttempts == 10) {
            numberOfUnsuccessfulAttempts = 0;
            throw new IllegalStateException("Превышено количество неудачных попыток");
        }
        introduceUsers(initiator, pretender);
        RandomNumberGenerator randomNumberGenerator = new RandomNumberGenerator();
        initiator.setRandomIdentifier(randomNumberGenerator.generateRandomBytes(64));
        initiator.setInitiatorIdentifier(generatingElement.modPow(new BigInteger(1, initiator.getRandomIdentifier()), groupModule));
        initiator.sendUserName();
        String initiatorName = new String(readMessageFromTransmissionChannel(), StandardCharsets.UTF_8);
        initiator.sendInitiatorIdentifier();
        pretender.setInitiatorIdentifier(new BigInteger(1, readMessageFromTransmissionChannel()).mod(groupModule));
        List<byte[]> initiatorData = pretender.getNamePasswordVerifierMap().get(initiatorName);
        byte[] initiatorSalt = initiatorData.get(0);
        byte[] initiatorVerifier = initiatorData.get(1);
        pretender.setRandomIdentifier(randomNumberGenerator.generateRandomBytes(64));
        pretender.setPretenderIdentifier(((kParameter.multiply(new BigInteger(1, initiatorVerifier).mod(groupModule)).mod(groupModule))
                .add(generatingElement.modPow(new BigInteger(1, pretender.getRandomIdentifier()).mod(groupModule), groupModule))).mod(groupModule));
        writeMessageToTransmissionChannel(initiatorSalt);
        byte[] saltFromPretender = readMessageFromTransmissionChannel();
        pretender.sendPretenderIdentifier();
        initiator.setPretenderIdentifier(new BigInteger(1, readMessageFromTransmissionChannel()).mod(groupModule));
        initiator.getSessionKeyForInitiator(saltFromPretender, initiator.userKey);
        pretender.getSessionKeyForPretender(initiator.name);
        byte[] initiatorKeyCheckMessage = initiator.getInitiatorKeyCheckMessage(saltFromPretender, initiator.name);
        writeMessageToTransmissionChannel(initiatorKeyCheckMessage);
        byte[] pretenderComputedInitiatorKeyCheckMessage = pretender.getInitiatorKeyCheckMessage(initiatorSalt, initiator.name);
        boolean isInitiatorAuthenticated = Arrays.equals(pretenderComputedInitiatorKeyCheckMessage, readMessageFromTransmissionChannel());
        if (!isInitiatorAuthenticated) {
            numberOfUnsuccessfulAttempts++;
            return false;
        }
        byte[] pretenderKeyCheckMessage = pretender.getPretenderKeyCheckMessage(pretenderComputedInitiatorKeyCheckMessage);
        writeMessageToTransmissionChannel(pretenderKeyCheckMessage);
        boolean isPretenderAuthenticated = Arrays.equals(initiator.getPretenderKeyCheckMessage(initiatorKeyCheckMessage), readMessageFromTransmissionChannel());
        if (!isPretenderAuthenticated) {
            numberOfUnsuccessfulAttempts++;
        }
        return isPretenderAuthenticated;
    }

    private void introduceUsers(UserOfSecureRemotePasswordProtocol initiator, UserOfSecureRemotePasswordProtocol
            pretender) {
        if (initiator.getPretenderNames().contains(pretender.name) && pretender.getNamePasswordVerifierMap().containsKey(initiator.name)) {
            return;
        }
        initiator.getPretenderNames().add(pretender.name);
        initiator.sendUserName();
        pretender.addUserNameFromChannel();
        initiator.sendSalt();
        pretender.addSaltFromChannel(initiator.name);
        initiator.sendPasswordVerifier();
        pretender.addPasswordVerifierFromChannel(initiator.name);
    }
}
