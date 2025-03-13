package io.blocksquare.sigxserver.security;

import org.springframework.stereotype.Service;

import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;

@Service
public class ChallangeService {
    // In production, consider using a distributed cache.
    private final ConcurrentHashMap<String, String> challenges = new ConcurrentHashMap<>();

    public String generateChallenge(String publicKey) {
        String challenge = UUID.randomUUID().toString();
        challenges.put(publicKey, challenge);
        return challenge;
    }

    public boolean verifyChallenge(String publicKey, String challenge) {
        System.out.println("[verifyChallenge] publicKey: " + publicKey);
        System.out.println("[verifyChallenge] challenge: " + challenge);
        System.out.println("challengesMap: " + challenges);
        return challenge != null && challenge.equals(challenges.get(publicKey));
    }

    public void removeChallenge(String publicKey) {
        challenges.remove(publicKey);
    }
}
