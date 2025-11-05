# RSA Web Application

A web-based RSA encryption tool built with Spring Boot and modern web technologies.

## Features

- RSA key pair generation with customizable key sizes (2048, 3072, or 4096 bits)
- File encryption using RSA public key
- File decryption using RSA private key
- Modern, responsive user interface using TailwindCSS
- Secure implementation with proper error handling

## Technical Stack

- Backend: Spring Boot
- Frontend: HTML, JavaScript, TailwindCSS
- Cryptography: Java BigInteger for RSA implementation
- Build Tool: Maven

## Getting Started

### Prerequisites

- Java 17 or higher
- Maven 3.6 or higher

### Running the Application

1. Clone the repository:
   ```bash
   git clone https://github.com/nikhilr-r/RSA-Cryptosystem-Command-Line-Tool-
   cd rsa-webapp
   ```

2. Build the project:
   ```bash
   mvn clean install
   ```

3. Run the application:
   ```bash
   mvn spring-boot:run
   ```

4. Open your browser and navigate to:
   ```
   http://localhost:8080
   ```

## Usage

1. Generate a Key Pair
   - Select your desired key size
   - Click "Generate Key Pair"
   - Save both public and private key components securely

2. Encrypt a File
   - Select the file to encrypt
   - Input the recipient's public key components
   - Click "Encrypt and Download"

3. Decrypt a File
   - Select the encrypted file
   - Input your private key components
   - Click "Decrypt and Download"

## Security Considerations

- Keep private keys secure and never share them
- Use strong key sizes (2048 bits minimum)
- This is a demonstration project and may need additional security measures for production use

## License

This project is licensed under the MIT License - see the LICENSE file for details.