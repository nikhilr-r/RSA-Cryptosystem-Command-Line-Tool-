package com.example.rsa_webapp.service;

import com.example.rsa_webapp.dto.KeyPairDto;
import org.springframework.stereotype.Service;
import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.Base64;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.Arrays;

@Service
public class RsaService {
    private static final int BLOCK_SIZE = 245; // For 2048-bit key (256 bytes - 11 bytes padding)

    public KeyPairDto generateKeys(int bitLength) {
        SecureRandom rand = new SecureRandom();
        BigInteger p = BigInteger.probablePrime(bitLength / 2, rand);
        BigInteger q;
        do {
            q = BigInteger.probablePrime(bitLength / 2, rand);
        } while (p.equals(q));

        BigInteger n = p.multiply(q);
        BigInteger phi_n = p.subtract(BigInteger.ONE).multiply(q.subtract(BigInteger.ONE));
        BigInteger e = new BigInteger("65537");
        BigInteger d = e.modInverse(phi_n);

        KeyPairDto.KeyDto publicKey = new KeyPairDto.KeyDto(n.toString(), e.toString());
        KeyPairDto.KeyDto privateKey = new KeyPairDto.KeyDto(n.toString(), d.toString());
        return new KeyPairDto(publicKey, privateKey);
    }

    public String encrypt(String plaintext, String nStr, String eStr) {
        BigInteger n = new BigInteger(nStr);
        BigInteger e = new BigInteger(eStr);
        BigInteger m = new BigInteger(plaintext.getBytes());
        BigInteger c = m.modPow(e, n);
        return Base64.getEncoder().encodeToString(c.toByteArray());
    }

    public String decrypt(String ciphertext, String nStr, String dStr) {
        BigInteger n = new BigInteger(nStr);
        BigInteger d = new BigInteger(dStr);
        byte[] decodedBytes = Base64.getDecoder().decode(ciphertext);
        BigInteger c = new BigInteger(decodedBytes);
        BigInteger m = c.modPow(d, n);
        return new String(m.toByteArray());
    }

    public byte[] encryptFile(byte[] fileData, String nStr, String eStr) throws IOException {
        BigInteger n = new BigInteger(nStr);
        BigInteger e = new BigInteger(eStr);
        ByteArrayOutputStream outputStream = new ByteArrayOutputStream();

        // Process file in blocks
        for (int i = 0; i < fileData.length; i += BLOCK_SIZE) {
            int blockSize = Math.min(BLOCK_SIZE, fileData.length - i);
            byte[] block = Arrays.copyOfRange(fileData, i, i + blockSize);
            
            // Encrypt block
            BigInteger m = new BigInteger(1, block);
            BigInteger c = m.modPow(e, n);
            byte[] encryptedBlock = c.toByteArray();
            
            // Write block size and encrypted block
            writeInt(outputStream, encryptedBlock.length);
            outputStream.write(encryptedBlock);
        }

        return outputStream.toByteArray();
    }

    public byte[] decryptFile(byte[] encryptedData, String nStr, String dStr) throws IOException {
        if (encryptedData == null || encryptedData.length == 0) {
            throw new IllegalArgumentException("Encrypted data is empty");
        }

        try {
            BigInteger n = new BigInteger(nStr);
            BigInteger d = new BigInteger(dStr);
            ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
            int position = 0;

            // Process blocks
            while (position < encryptedData.length) {
                if (position + 4 > encryptedData.length) {
                    throw new IllegalArgumentException("Invalid encrypted file format: incomplete block size");
                }

                // Read block size
                int blockSize = readInt(encryptedData, position);
                if (blockSize <= 0 || blockSize > 256) { // Max block size for 2048-bit key
                    throw new IllegalArgumentException("Invalid block size: " + blockSize);
                }
                position += 4;

                if (position + blockSize > encryptedData.length) {
                    throw new IllegalArgumentException("Invalid encrypted file format: incomplete block");
                }
                
                // Read and decrypt block
                byte[] encryptedBlock = Arrays.copyOfRange(encryptedData, position, position + blockSize);
                BigInteger c = new BigInteger(1, encryptedBlock); // Use 1 as signum to treat as positive
                
                // Check if the encrypted block is valid
                if (c.compareTo(n) >= 0) {
                    throw new IllegalArgumentException("Invalid encrypted block: value larger than modulus");
                }
                
                BigInteger m = c.modPow(d, n);
                byte[] decryptedBlock = m.toByteArray();
                
                // Remove padding if present
                if (decryptedBlock.length > 0 && decryptedBlock[0] == 0) {
                    decryptedBlock = Arrays.copyOfRange(decryptedBlock, 1, decryptedBlock.length);
                }
                
                outputStream.write(decryptedBlock);
                position += blockSize;
            }

            byte[] result = outputStream.toByteArray();
            if (result.length == 0) {
                throw new IllegalArgumentException("Decryption resulted in empty data");
            }
            
            return result;

        } catch (NumberFormatException e) {
            throw new IllegalArgumentException("Invalid key format: " + e.getMessage());
        } catch (ArithmeticException e) {
            throw new IllegalArgumentException("Decryption error: Invalid key values");
        } catch (Exception e) {
            throw new IOException("Decryption failed: " + e.getMessage(), e);
        }
    }

    private void writeInt(ByteArrayOutputStream outputStream, int value) {
        outputStream.write((value >> 24) & 0xFF);
        outputStream.write((value >> 16) & 0xFF);
        outputStream.write((value >> 8) & 0xFF);
        outputStream.write(value & 0xFF);
    }

    private int readInt(byte[] data, int offset) {
        return ((data[offset] & 0xFF) << 24) |
               ((data[offset + 1] & 0xFF) << 16) |
               ((data[offset + 2] & 0xFF) << 8) |
               (data[offset + 3] & 0xFF);
    }
}