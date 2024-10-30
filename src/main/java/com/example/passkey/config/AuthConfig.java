package com.example.passkey.config;

import com.example.passkey.repository.InMemoryCredentialRepository;
import com.yubico.webauthn.RelyingParty;
import com.yubico.webauthn.data.RelyingPartyIdentity;
import java.util.Set;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class AuthConfig {

    @Autowired
    InMemoryCredentialRepository inMemoryCredentialRepository;

    @Bean
    public RelyingParty relyingParty() {
        RelyingPartyIdentity rpIdentity = RelyingPartyIdentity.builder()
                .id("www.fromitive.site")
                .name("passkey 예제")
                .build();

        // CredentialRepository 인스턴스 생성
        return RelyingParty.builder()
                .identity(rpIdentity)
                .credentialRepository(inMemoryCredentialRepository)
                .origins(Set.of("https://www.fromitive.site"))
                .build();
    }
}
