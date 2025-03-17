package io.blocksquare.sigxserver.controller;

import io.blocksquare.sigxserver.entity.WalletInfo;
import io.blocksquare.sigxserver.entity.WalletInfoDTO;
import io.blocksquare.sigxserver.repository.WalletInfoRepository;
import io.blocksquare.sigxserver.repository.WalletUserRepository;
import io.blocksquare.sigxserver.security.WalletUserDetails;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

import java.math.BigDecimal;
import java.time.LocalDateTime;
import java.util.Map;

@RestController
@RequiredArgsConstructor
public class UserController {

    private final WalletInfoRepository walletInfoRepository;

    @GetMapping("/profile")
    public WalletUserDetails profile(@AuthenticationPrincipal WalletUserDetails userDetails) {
        return userDetails;
    }

    @PostMapping("/sendwalletinfo")
    public boolean insertWalletInfo(@RequestBody WalletInfoDTO walletInfo) {

        try {
            String walletName = walletInfo.getWalletName();
            String publicKey = walletInfo.getPublicKey();
            BigDecimal sigx = walletInfo.getSigx();

            WalletInfo userInfo = walletInfoRepository.findByPublicKey(publicKey);

            if (userInfo == null) {
                userInfo = new WalletInfo();
                userInfo.setWalletName(walletName);
                userInfo.setPublicKey(publicKey);
                userInfo.setSigx(sigx);
                userInfo.setCreatedAt(LocalDateTime.now());
            }

            // Always update updatedAt
            userInfo.setUpdatedAt(LocalDateTime.now());

            WalletInfo savedWallet = walletInfoRepository.save(userInfo);

            return savedWallet.getId() != null;

        } catch (Exception e) {
            throw new RuntimeException(e.getMessage());
        }
    }
}
