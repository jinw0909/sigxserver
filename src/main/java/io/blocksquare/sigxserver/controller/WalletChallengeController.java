package io.blocksquare.sigxserver.controller;

import io.blocksquare.sigxserver.security.ChallangeService;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequiredArgsConstructor
public class WalletChallengeController {

    private final ChallangeService challangeService;

    @GetMapping("/auth/challenge")
    public String generateChallenge(@RequestParam("publicKey") String publicKey) {
        //Generate and return the challenge for the provided public key
        return challangeService.generateChallenge(publicKey);
    }

}
