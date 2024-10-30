package com.example.passkey.controller;

import com.example.passkey.service.AssertionService;
import com.example.passkey.service.RegisterationService;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.yubico.webauthn.AssertionRequest;
import com.yubico.webauthn.data.AuthenticatorAssertionResponse;
import com.yubico.webauthn.data.AuthenticatorAttestationResponse;
import com.yubico.webauthn.data.ClientAssertionExtensionOutputs;
import com.yubico.webauthn.data.ClientRegistrationExtensionOutputs;
import com.yubico.webauthn.data.PublicKeyCredential;
import com.yubico.webauthn.data.PublicKeyCredentialCreationOptions;
import com.yubico.webauthn.exception.AssertionFailedException;
import jakarta.servlet.http.HttpSession;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class AuthController {

    private final RegisterationService registerationService;
    private final AssertionService assertionService;

    public AuthController(RegisterationService registerationService, AssertionService assertionService) {
        this.registerationService = registerationService;
        this.assertionService = assertionService;
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
            , HttpSession session) {
        PublicKeyCredentialCreationOptions options = (PublicKeyCredentialCreationOptions) session.getAttribute(
                "options");
        String userName = (String) session.getAttribute("name");
        registerationService.finish(options, credential, userName);
        return ResponseEntity.ok().build();
    }

    @GetMapping("/assertion/request")
    public ResponseEntity<String> startAssertion(@RequestParam String userName, HttpSession session)
            throws JsonProcessingException {
        AssertionRequest request = assertionService.start(userName);
        session.setAttribute("assertionRequestOptions", request);
        String credentialGetJson = request.toCredentialsGetJson();
        return ResponseEntity.ok(credentialGetJson);
    }

    @PostMapping("/assertion/finish")
    public ResponseEntity<String> finishAssertion(
            @RequestBody PublicKeyCredential<AuthenticatorAssertionResponse, ClientAssertionExtensionOutputs> credential,
            HttpSession session) throws AssertionFailedException {

        AssertionRequest request = (AssertionRequest) session.getAttribute("assertionRequestOptions");
        String userName = assertionService.finish(request, credential);

        return ResponseEntity.ok(userName);
    }
}
