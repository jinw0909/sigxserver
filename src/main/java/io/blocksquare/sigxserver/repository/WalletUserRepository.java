package io.blocksquare.sigxserver.repository;

import io.blocksquare.sigxserver.entity.WalletUser;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface WalletUserRepository extends JpaRepository<WalletUser, Long> {
    WalletUser findByPublicKey(String publicKey);
}
