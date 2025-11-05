package com.example.rsa_webapp.dto;
import lombok.Data;

@Data
public class DecryptRequestDto {
    private String ciphertext;
    private String modulus;
    private String exponent;
}