package com.example.rsa_webapp.dto;
import lombok.Data;

@Data
public class EncryptRequestDto {
    private String text;
    private String modulus;
    private String exponent;
}