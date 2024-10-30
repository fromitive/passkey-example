package com.example.passkey.service;

import com.example.passkey.repository.InMemoryCredentialRepository;
import com.yubico.webauthn.FinishRegistrationOptions;
import com.yubico.webauthn.RegisteredCredential;
import com.yubico.webauthn.RelyingParty;
import com.yubico.webauthn.StartRegistrationOptions;
import com.yubico.webauthn.data.AuthenticatorAttestationResponse;
import com.yubico.webauthn.data.ByteArray;
import com.yubico.webauthn.data.ClientRegistrationExtensionOutputs;
import com.yubico.webauthn.data.PublicKeyCredential;
import com.yubico.webauthn.data.PublicKeyCredentialCreationOptions;
import com.yubico.webauthn.data.UserIdentity;
import com.yubico.webauthn.exception.RegistrationFailedException;
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

    public void finish(PublicKeyCredentialCreationOptions options,
                       PublicKeyCredential<AuthenticatorAttestationResponse, ClientRegistrationExtensionOutputs> credential,
                       String userName) {
        try {
            relyingParty.finishRegistration(
                    FinishRegistrationOptions.builder().request(options)
                            .response(credential)
                            .build()
            );
            saveCredential(options, credential, userName);
        } catch (RegistrationFailedException e) {
            throw new RuntimeException(e);
        }
    }

    private void saveCredential(PublicKeyCredentialCreationOptions options,
                                PublicKeyCredential<AuthenticatorAttestationResponse, ClientRegistrationExtensionOutputs> credential,
                                String userName) {
        RegisteredCredential registeredCredential = RegisteredCredential.builder()
                .credentialId(credential.getId())
                .userHandle(options.getUser().getId())
                .publicKeyCose(getPublicKeyCose(credential))
                .build();
        inMemoryCredentialRepository.addCredential(userName, registeredCredential);
    }

    private ByteArray getPublicKeyCose(
            PublicKeyCredential<AuthenticatorAttestationResponse, ClientRegistrationExtensionOutputs> credential) {
        AuthenticatorAttestationResponse response = credential.getResponse();
        return response.getAttestation().getAuthenticatorData().getAttestedCredentialData().get()
                .getCredentialPublicKey();
    }
}
