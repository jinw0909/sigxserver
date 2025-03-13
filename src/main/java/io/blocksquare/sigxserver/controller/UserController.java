package io.blocksquare.sigxserver.controller;

import io.blocksquare.sigxserver.security.WalletUserDetails;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class UserController {

    @GetMapping("/profile")
    public WalletUserDetails profile(@AuthenticationPrincipal WalletUserDetails userDetails) {
        return userDetails;
    }
}
