package com.example.passkey.repository;

import com.yubico.webauthn.CredentialRepository;
import com.yubico.webauthn.RegisteredCredential;
import com.yubico.webauthn.data.ByteArray;
import com.yubico.webauthn.data.PublicKeyCredentialDescriptor;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.stream.Collectors;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

@Component
public class InMemoryCredentialRepository implements CredentialRepository {

    private static final Logger log = LoggerFactory.getLogger(InMemoryCredentialRepository.class);
    private final Map<ByteArray, List<RegisteredCredential>> credentials = new ConcurrentHashMap<>();
    private final Map<String, ByteArray> userIdMapping = new ConcurrentHashMap<>();

    @Override
    public Set<PublicKeyCredentialDescriptor> getCredentialIdsForUsername(String username) {
        ByteArray userId = userIdMapping.get(username);
        if (userId == null) {
            return Collections.emptySet();
        }
        return credentials.getOrDefault(userId, Collections.emptyList()).stream()
                .map(registeredCredential ->
                        PublicKeyCredentialDescriptor.builder()
                                .id(registeredCredential.getCredentialId())
                                .build())
                .collect(Collectors.toSet());
    }

    @Override
    public Optional<ByteArray> getUserHandleForUsername(String username) {
        return Optional.ofNullable(userIdMapping.get(username));
    }

    @Override
    public Optional<String> getUsernameForUserHandle(ByteArray userHandle) {
        return userIdMapping.entrySet().stream()
                .filter(entry -> entry.getValue().equals(userHandle))
                .map(Map.Entry::getKey)
                .findFirst();
    }

    @Override
    public Set<RegisteredCredential> lookupAll(ByteArray credentialId) {
        return credentials.values().stream()
                .flatMap(Collection::stream)
                .filter(cred -> cred.getCredentialId().equals(credentialId))
                .collect(Collectors.toSet());
    }

    @Override
    public Optional<RegisteredCredential> lookup(ByteArray credentialId, ByteArray userHandle) {
        return credentials.getOrDefault(userHandle, Collections.emptyList()).stream()
                .filter(cred -> cred.getCredentialId().equals(credentialId))
                .findFirst();
    }

    public void addCredential(String username, RegisteredCredential credential) {
        ByteArray userId = userIdMapping.computeIfAbsent(username, (k) -> credential.getUserHandle());
        List<RegisteredCredential> registeredCredentials = credentials.computeIfAbsent(userId, k -> new ArrayList<>());
        registeredCredentials.add(credential);
    }

    public void updateSignatureCount(String username, ByteArray credentialId, long newSignatureCount) {
        ByteArray userId = userIdMapping.get(username);
        if (userId == null) {
            return;
        }

        List<RegisteredCredential> userCredentials = credentials.get(userId);
        if (userCredentials != null) {
            List<RegisteredCredential> updatedCredentials = userCredentials.stream()
                    .map(credential -> updateCredential(credentialId, credential, newSignatureCount))
                    .toList();
            credentials.put(userId, updatedCredentials);
        }
    }

    private RegisteredCredential updateCredential(ByteArray credentialId, RegisteredCredential credential,
                                                  long newSignatureCount) {
        if (credential.getCredentialId().equals(credentialId)) {
            log.info("newSignatureCount : {}", newSignatureCount);
            return RegisteredCredential.builder()
                    .credentialId(credential.getCredentialId())
                    .userHandle(credential.getUserHandle())
                    .publicKeyCose(credential.getPublicKeyCose())
                    .signatureCount(newSignatureCount)
                    .build();
        }
        return credential;
    }
}
