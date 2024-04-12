package com.security.security.service;

import java.security.Key;
import java.util.Base64;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.management.RuntimeErrorException;

import org.springframework.stereotype.Service;

import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
@Service
public class JwtService {

    private String seceretKey;

    public JwtService(){
        seceretKey=generateSeceretKey();
    }


    public String generateSeceretKey(){
        try{
            KeyGenerator keyGen=KeyGenerator.getInstance("HmacSHA256");
            SecretKey secretKey = keyGen.generateKey();
            return Base64.getEncoder().encodeToString(secretKey.getEncoded());
        }catch(Exception e){
            throw new RuntimeErrorException(null, "error generating seceret key");
        }
    }




    public String getToken(String name) {
        // https://jwt.io/

        Map<String,Object> claims=new HashMap();

        return Jwts.builder()
                    .setClaims(claims)
                    .setSubject(name)
                    .setIssuedAt(new Date(System.currentTimeMillis()))
                    .setExpiration(new Date(System.currentTimeMillis() + 1000*60*3))
                    .signWith(getKey(),SignatureAlgorithm.HS256).compact();
        
    }

    private Key getKey() {
        byte[] keybytes=Decoders.BASE64.decode(seceretKey);
        return Keys.hmacShaKeyFor(keybytes);
    }
    
}
