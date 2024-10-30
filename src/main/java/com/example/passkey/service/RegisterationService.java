package com.example.passkey.service;

import com.example.passkey.repository.InMemoryCredentialRepository;
import com.yubico.webauthn.RelyingParty;
import com.yubico.webauthn.StartRegistrationOptions;
import com.yubico.webauthn.data.ByteArray;
import com.yubico.webauthn.data.PublicKeyCredentialCreationOptions;
import com.yubico.webauthn.data.UserIdentity;
import org.springframework.stereotype.Service;

@Service
public class RegisterationService {

    private final RelyingParty relyingParty;
    private final HandleGenerator handleGenerator;
    private final InMemoryCredentialRepository inMemoryCredentialRepository;

    public RegisterationService(RelyingParty relyingParty, HandleGenerator handleGenerator,
                                InMemoryCredentialRepository inMemoryCredentialRepository) {
        this.relyingParty = relyingParty;
        this.handleGenerator = handleGenerator;
        this.inMemoryCredentialRepository = inMemoryCredentialRepository;
    }

    public PublicKeyCredentialCreationOptions start(String userName) {
        ByteArray userHandle = inMemoryCredentialRepository.getUserHandleForUsername(userName)
                .orElseGet(() -> handleGenerator.generateRandom(32));
        return relyingParty.startRegistration(
                StartRegistrationOptions.builder()
                        .user(UserIdentity.builder()
                                .name(userName)
                                .displayName(userName)
                                .id(userHandle)
                                .build())
                        .build());
    }
}
