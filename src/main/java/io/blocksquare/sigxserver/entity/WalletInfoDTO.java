package io.blocksquare.sigxserver.entity;

import lombok.Data;

import java.math.BigDecimal;

@Data
public class WalletInfoDTO {
    private String publicKey;
    private String walletName;
    private BigDecimal sigx;
}
