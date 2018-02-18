/*
The RSA encryption process was commissioned in the 70's by Ron Rivest, Adi
Shamir, and Leonard Adleman and articulates an asymmetric method of data
ciphering with a key-pair of integers. Mod inverse properties of primes
are used to encode and return an original script while spending a single-use
permutation in a generated, finite mathematical group that meets a bit-size
requirement.

The method is demoed in the following program code.

Public Key: ( n , e )
Private Key: ( n , d ) or ( d , p , q ) or ( n , d, phi )
looks like: [ ( n , e ) , d ]

p , q : large primes
n = p * q
phi = (p - 1) * (q - 1)
choose e < phi : gcd(e, phi) = 1
choose d < phi : d * e mod( phi ) = 1 (i.e. inverse of e in phi)
*/

import java.util.Random;
import java.util.List;
import java.util.Arrays;
import java.util.LinkedList;
import java.util.ArrayList;
import java.util.Scanner;
import java.math.BigInteger;
import java.security.SecureRandom;

public class RSABigInteger{

  private final static SecureRandom random = new SecureRandom();
  private BigInteger public_exp; // the public exponent, public key, e
  private BigInteger secret_exp; // the secret exponent, private key, d
  private BigInteger modulus; // an N-bit product of two primes


// the constructor of the encryption function. Generates e, d, phi, and n from
// two randomly generated BigInteger primes.
  public RSABigInteger(int N){
    BigInteger q = BigInteger.probablePrime(N/2, random);
    BigInteger p = BigInteger.probablePrime(N/2, random);
    while(q.equals(p)){p = BigInteger.probablePrime(N/2, random);}

    modulus = p.multiply(q);
    BigInteger phi = p.subtract(BigInteger.ONE).multiply(q.subtract(BigInteger.ONE));
    do {public_exp = new BigInteger(N, random);
    }while(!phi.gcd(public_exp).equals(BigInteger.ONE) // gcd( e, phi) != 1
      || phi.compareTo(public_exp) <= 0 // e >= phi
      || public_exp.compareTo(BigInteger.ONE) <= 0); // e = 1
    secret_exp = public_exp.modInverse(phi);
  }

// data encryption, data^e mod m
  BigInteger encrypt(BigInteger data){
    return data.modPow(public_exp, modulus);
  }

// decryption, secret^d mod m
  BigInteger decrypt(BigInteger encrypted){
    return encrypted.modPow(secret_exp, modulus);
  }

  public static void main(String[] args){

    // introduction to the program and collection of data
    Scanner input = new Scanner(System.in);
    System.out.println("Welcome to RSA Encryption.");
    System.out.println("Please enter your secret information: ");
    String in = input.nextLine();

    // convert input to byte representation
    byte[] bytes = in.getBytes();
    BigInteger message = new BigInteger(bytes);
    String mes = new String(bytes);
    System.out.println("You typed in: " + mes);

    // create an RSA object of defined bit size. encrypt and decrypt the info.
    RSABigInteger rsa = new RSABigInteger(1024); // between 1024-bit and 4096-bit security is standard
    BigInteger encrypted = rsa.encrypt(message);
    String decrypted = new String(rsa.decrypt(encrypted).toByteArray());

    // return information
    System.out.println("Encrypted: " + new String(encrypted.toByteArray())); // shows the encrypted values
    System.out.println("Your original message was: " + decrypted);
  }
}
