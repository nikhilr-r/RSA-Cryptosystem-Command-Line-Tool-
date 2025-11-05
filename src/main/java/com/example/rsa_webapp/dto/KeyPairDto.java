package com.example.rsa_webapp.dto;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data @NoArgsConstructor @AllArgsConstructor
public class KeyPairDto {
    private KeyDto publicKey;
    private KeyDto privateKey;

    @Data @NoArgsConstructor @AllArgsConstructor
    public static class KeyDto {
        private String modulus;
        private String exponent;
    }
}