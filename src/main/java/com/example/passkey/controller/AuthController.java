package com.example.passkey.controller;

import com.example.passkey.repository.InMemoryCredentialRepository;
import com.example.passkey.service.RegisterationService;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.yubico.webauthn.AssertionRequest;
import com.yubico.webauthn.AssertionResult;
import com.yubico.webauthn.FinishAssertionOptions;
import com.yubico.webauthn.FinishRegistrationOptions;
import com.yubico.webauthn.RegisteredCredential;
import com.yubico.webauthn.RegistrationResult;
import com.yubico.webauthn.RelyingParty;
import com.yubico.webauthn.StartAssertionOptions;
import com.yubico.webauthn.data.AuthenticatorAssertionResponse;
import com.yubico.webauthn.data.AuthenticatorAttestationResponse;
import com.yubico.webauthn.data.ByteArray;
import com.yubico.webauthn.data.ClientAssertionExtensionOutputs;
import com.yubico.webauthn.data.ClientRegistrationExtensionOutputs;
import com.yubico.webauthn.data.PublicKeyCredential;
import com.yubico.webauthn.data.PublicKeyCredentialCreationOptions;
import com.yubico.webauthn.exception.AssertionFailedException;
import com.yubico.webauthn.exception.RegistrationFailedException;
import jakarta.servlet.http.HttpSession;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class AuthController {

    private final RelyingParty relyingParty;
    private final RegisterationService registerationService;
    private final InMemoryCredentialRepository inMemoryCredentialRepository;

    public AuthController(RelyingParty relyingParty, RegisterationService registerationService,
                          InMemoryCredentialRepository inMemoryCredentialRepository) {
        this.relyingParty = relyingParty;
        this.registerationService = registerationService;
        this.inMemoryCredentialRepository = inMemoryCredentialRepository;
    }

    @GetMapping("/register/request")
    public ResponseEntity<PublicKeyCredentialCreationOptions> startRegistration(@RequestParam String userName,
                                                                                HttpSession httpSession) {
        PublicKeyCredentialCreationOptions options = registerationService.start(userName);
        httpSession.setAttribute("options", options);
        httpSession.setAttribute("name", userName);
        return ResponseEntity.ok(options);
    }

    @PostMapping("/register/finish")
    public ResponseEntity<Void> finishRegistration(
            @RequestBody PublicKeyCredential<AuthenticatorAttestationResponse, ClientRegistrationExtensionOutputs> credential
            , HttpSession session) throws RegistrationFailedException {

        PublicKeyCredentialCreationOptions options = (PublicKeyCredentialCreationOptions) session.getAttribute(
                "options");
        String userName = (String) session.getAttribute("name");
        RegistrationResult result = relyingParty.finishRegistration(
                FinishRegistrationOptions.builder().request(options)
                        .response(credential)
                        .build()
        );

        AuthenticatorAttestationResponse response = credential.getResponse();
        ByteArray publicKey = response.getAttestation().getAuthenticatorData().getAttestedCredentialData().get()
                .getCredentialPublicKey();

        RegisteredCredential registeredCredential = RegisteredCredential.builder()
                .credentialId(credential.getId())
                .userHandle(options.getUser().getId())
                .publicKeyCose(publicKey)
                .build();

        inMemoryCredentialRepository.addCredential(userName, registeredCredential);
        return ResponseEntity.ok().build();
    }

    @GetMapping("/assertion/request")
    public ResponseEntity<String> startAssertion(@RequestParam String username, HttpSession session)
            throws JsonProcessingException {
        AssertionRequest assertionRequest = relyingParty.startAssertion(StartAssertionOptions.builder()
                .username(username)     // Or .userHandle(ByteArray) if preferred
                .build());
        session.setAttribute("assertionRequestOptions", assertionRequest);
        String credentialGetJson = assertionRequest.toCredentialsGetJson();

        return ResponseEntity.ok(credentialGetJson);
    }

    @PostMapping("/assertion/finish")
    public ResponseEntity<String> finishAssertion(
            @RequestBody PublicKeyCredential<AuthenticatorAssertionResponse, ClientAssertionExtensionOutputs> credential,
            HttpSession session) throws AssertionFailedException {

        AssertionRequest options = (AssertionRequest) session.getAttribute("assertionRequestOptions");
        AssertionResult result = relyingParty.finishAssertion(
                FinishAssertionOptions.builder()
                        .request(options)
                        .response(credential)
                        .build()
        );
        if (result.isSuccess()) {
            String username = result.getUsername();
            ByteArray credentialId = credential.getId();
            long newSignatureCount = result.getSignatureCount();
            inMemoryCredentialRepository.updateSignatureCount(username, credentialId, newSignatureCount);
            return ResponseEntity.ok(result.getUsername());
        }
        throw new RuntimeException("Authentication failed");
    }
}
