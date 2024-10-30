package com.example.passkey.service;

import com.example.passkey.repository.InMemoryCredentialRepository;
import com.yubico.webauthn.AssertionRequest;
import com.yubico.webauthn.AssertionResult;
import com.yubico.webauthn.FinishAssertionOptions;
import com.yubico.webauthn.RelyingParty;
import com.yubico.webauthn.StartAssertionOptions;
import com.yubico.webauthn.data.AuthenticatorAssertionResponse;
import com.yubico.webauthn.data.ByteArray;
import com.yubico.webauthn.data.ClientAssertionExtensionOutputs;
import com.yubico.webauthn.data.PublicKeyCredential;
import com.yubico.webauthn.exception.AssertionFailedException;
import org.springframework.stereotype.Service;

@Service
public class AssertionService {

    private final InMemoryCredentialRepository inMemoryCredentialRepository;
    private final RelyingParty relyingParty;

    public AssertionService(InMemoryCredentialRepository inMemoryCredentialRepository, RelyingParty relyingParty) {
        this.inMemoryCredentialRepository = inMemoryCredentialRepository;
        this.relyingParty = relyingParty;
    }

    public AssertionRequest start(String userName) {
        return relyingParty.startAssertion(StartAssertionOptions.builder()
                .username(userName)
                .build());
    }

    public String finish(AssertionRequest request,
                         PublicKeyCredential<AuthenticatorAssertionResponse, ClientAssertionExtensionOutputs> credential)
            throws AssertionFailedException {
        
        AssertionResult result = relyingParty.finishAssertion(
                FinishAssertionOptions.builder()
                        .request(request)
                        .response(credential)
                        .build());

        if (result.isSuccess()) {
            String username = result.getUsername();
            ByteArray credentialId = credential.getId();
            long newSignatureCount = result.getSignatureCount();
            inMemoryCredentialRepository.updateSignatureCount(username, credentialId, newSignatureCount);
            return result.getUsername();
        }
        throw new AssertionFailedException("Assertion Failed");
    }
}
