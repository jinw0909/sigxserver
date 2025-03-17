package io.blocksquare.sigxserver.repository;

import io.blocksquare.sigxserver.entity.WalletInfo;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface WalletInfoRepository extends JpaRepository<WalletInfo, Long> {

    WalletInfo findByPublicKey(String publicKey);
}
