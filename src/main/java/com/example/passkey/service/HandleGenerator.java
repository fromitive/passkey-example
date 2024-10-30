package com.example.passkey.service;

import com.yubico.webauthn.data.ByteArray;
import java.security.SecureRandom;
import org.springframework.stereotype.Service;

@Service
public class HandleGenerator {
    private static final SecureRandom random = new SecureRandom();

    public ByteArray generateRandom(int length) {
        byte[] bytes = new byte[length];
        random.nextBytes(bytes);
        return new ByteArray(bytes);
    }
}
