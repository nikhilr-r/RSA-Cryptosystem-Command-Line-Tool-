package com.example.rsa_webapp.controller;

import com.example.rsa_webapp.dto.DecryptRequestDto;
import com.example.rsa_webapp.dto.EncryptRequestDto;
import com.example.rsa_webapp.dto.KeyPairDto;
import com.example.rsa_webapp.service.RsaService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;
import java.math.BigInteger;

import java.io.IOException;

@RestController
@RequestMapping("/api/rsa")
public class RsaController {

    @Autowired
    private RsaService rsaService;

    @PostMapping("/generate")
    public ResponseEntity<KeyPairDto> generateKeys(@RequestParam(defaultValue = "2048") int bitLength) {
        return ResponseEntity.ok(rsaService.generateKeys(bitLength));
    }

    @PostMapping("/encrypt")
    public ResponseEntity<String> encrypt(@RequestBody EncryptRequestDto request) {
        return ResponseEntity.ok(rsaService.encrypt(request.getText(), request.getModulus(), request.getExponent()));
    }

    @PostMapping("/decrypt")
    public ResponseEntity<String> decrypt(@RequestBody DecryptRequestDto request) {
        return ResponseEntity.ok(rsaService.decrypt(request.getCiphertext(), request.getModulus(), request.getExponent()));
    }

    @PostMapping("/encrypt-file")
    public ResponseEntity<byte[]> encryptFile(
            @RequestParam("file") MultipartFile file,
            @RequestParam("modulus") String modulus,
            @RequestParam("exponent") String exponent) throws IOException {
        
        byte[] encryptedData = rsaService.encryptFile(file.getBytes(), modulus, exponent);
        
        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_OCTET_STREAM);
        headers.setContentDispositionFormData("attachment", "encrypted.bin");
        
        return ResponseEntity.ok()
                .headers(headers)
                .body(encryptedData);
    }

    @PostMapping("/decrypt-file")
    public ResponseEntity<?> decryptFile(
            @RequestParam("file") MultipartFile file,
            @RequestParam("modulus") String modulus,
            @RequestParam("exponent") String exponent) {
        try {
            if (file.isEmpty()) {
                return ResponseEntity.badRequest().body("File is empty");
            }
            
            // Validate modulus and exponent
            try {
                new BigInteger(modulus);
                new BigInteger(exponent);
            } catch (NumberFormatException e) {
                return ResponseEntity.badRequest().body("Invalid key format");
            }
            
            byte[] decryptedData = rsaService.decryptFile(file.getBytes(), modulus, exponent);
            
            if (decryptedData == null || decryptedData.length == 0) {
                return ResponseEntity.badRequest().body("Decryption failed");
            }
            
            HttpHeaders headers = new HttpHeaders();
            headers.setContentType(MediaType.APPLICATION_OCTET_STREAM);
            headers.setContentDispositionFormData("attachment", 
                file.getOriginalFilename().replaceFirst("\\.encrypted$", ".decrypted"));
            
            return ResponseEntity.ok()
                    .headers(headers)
                    .body(decryptedData);
                    
        } catch (Exception e) {
            e.printStackTrace(); // Log the error
            return ResponseEntity.status(500)
                    .body("Decryption error: " + e.getMessage());
        }
    }
}