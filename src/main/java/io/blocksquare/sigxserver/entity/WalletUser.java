package io.blocksquare.sigxserver.entity;

import jakarta.persistence.*;
import lombok.Data;

import java.math.BigDecimal;
import java.time.LocalDateTime;

@Entity
@Data
public class WalletUser {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    private String walletName;

    @Column(unique = true)
    private String publicKey;

    @Column(precision = 16, scale = 8)
    private BigDecimal sigx;

    private LocalDateTime createdAt;
    private LocalDateTime updatedAt;

    private String role;
}
