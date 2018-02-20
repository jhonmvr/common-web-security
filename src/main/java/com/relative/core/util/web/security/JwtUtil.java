package com.relative.core.util.web.security;

import java.security.Key;
import java.util.Date;

import javax.crypto.spec.SecretKeySpec;
import javax.xml.bind.DatatypeConverter;

import ec.fin.segurossucre.core.exception.SegSucreException;
import ec.fin.segurossucre.core.util.enums.LanguageEnum;
import ec.fin.segurossucre.core.util.main.Constantes;
import ec.fin.segurossucre.core.util.main.Usuario;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.JwtBuilder;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.MalformedJwtException;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.UnsupportedJwtException;

/**
 * Clase utilitaria para la generacion de json web tokens
 * @author LUIS TAMAYO RELATIVE ENGINE
 *
 */

public class JwtUtil {

/**
 * {@code  
  		Usuario u = new Usuario();
           u.setNombre("luis.tamayo");
           u.setId("luis.tamayo");
           String myToken = generateJWTCmplex( u , 1800000);
           System.out.println("token: " + myToken);
           try {
				parseJWTComplex("eyJhbGciOiJIUzI1NiJ9.eyJqdGkiOiJsdWlzLnRhbWF5byIsImlhdCI6MTUxODEwMjg0NCwic3ViIjoibHVpcy50YW1heW8iLCJpc3MiOiJ3d3cucmVsYXRpdmUtZW5naW5lLmNvbSIsImV4cCI6MTUxODEwMjg0N30.i3gnloRj0UES-3mMvJt-RyXjzn4fmeZFOQ4RznzqjV8");
			} catch (SegSucreException e) {
				e.printStackTrace();
			}
	}
 * @param args
 */
	   public static void main(String[] args ){
		   //NO IMPLEMENTATION
		   
		   
	   }

	    /**
	     * Intenta analizar la cadena especificada como un token JWT. Si tiene éxito, devuelve el objeto Usuario con nombre de usuario, id y función prefilled (extraído de token).
	     * Si no tiene éxito (el token no es válido o no contiene todas las propiedades de usuario necesarias), simplemente devuelve null.
	     * 
	     * @param token  JWT token a parsear
	     * @return  El objeto de usuario extraído de token especificado o null si un token no es válido.
	     */
	    public static Usuario parseJWTSimple(String token) {
	        try {
	            Claims body = Jwts.parser()
	                    .setSigningKey(Constantes.CRYPTO_JWT)
	                    .parseClaimsJws(token)
	                    .getBody();
	            
	            Usuario u = new Usuario();
	            u.setNombre(body.getSubject());
	            u.setId((String) body.get("userId"));
	            u.setRole((String) body.get("role"));

	            return u;

	        } catch (JwtException  e) {
	            return null;
	        }catch ( ClassCastException e) {
	            return null;
	        }
	    }

	    /**
	     * Genera un token JWT que contiene el nombre de usuario como asunto y userId y el rol como reclamaciones adicionales. 
	     * Estas propiedades se toman del objeto de usuario especificado. La validez de las fichas es infinita.
	     * 
	     * @param u El usuario para el que se generará el token
	     * @return JWT token
	     */
	    public static String generateJWTSimple(Usuario u) {
	        Claims claims = Jwts.claims().setSubject(u.getNombre());
	        claims.put("userId", u.getId() + "");
	        claims.put("role", u.getRole());

	        return Jwts.builder()
	                .setClaims(claims)
	                .signWith(SignatureAlgorithm.HS512, Constantes.CRYPTO_JWT)
	                .compact();
	    }
	    
	    /**
	     * Metodo que genera JWT en funcion de la informacion del usuario y un time to live del token.
	     * Se aplica criptografia HS256.
	     * Llena la reclacion que se envia al cliente con la informacion recibida
	     * @param u Usuario con la informacion para generar el token y enviar en la reclamacion.
	     * @param ttlMillis Time to live del token
	     * @return Token generado
	     */
	    public static String generateJWTCmplex(Usuario u, long ttlMillis) {

	        //The JWT signature algorithm we will be using to sign the token
	        SignatureAlgorithm signatureAlgorithm = SignatureAlgorithm.HS256;
	        long nowMillis =System.currentTimeMillis();
	        Date now = new Date(nowMillis);
	        //We will sign our JWT with our ApiKey secret
	        byte[] apiKeySecretBytes = DatatypeConverter.parseBase64Binary(Constantes.CRYPTO_JWT);
	        Key signingKey = new SecretKeySpec(apiKeySecretBytes, signatureAlgorithm.getJcaName());

	        //Let's set the JWT Claims
	        JwtBuilder builder = Jwts.builder().setId(u.getId())
	                                    .setIssuedAt(now)
	                                    .setSubject(u.getId())
	                                    .setIssuer(Constantes.ISSUER_JWT)
	                                    .signWith(signatureAlgorithm, signingKey);

	        //if it has been specified, let's add the expiration
	        if (ttlMillis >= 0) {
	        long expMillis = nowMillis + ttlMillis;
	            Date exp = new Date(expMillis);
	            builder.setExpiration(exp);
	        }

	        //Builds the JWT and serializes it to a compact, URL-safe string
	        return builder.compact();
	    }
	    
	    /**
	     * Intenta analizar la cadena especificada como un token JWT. Si tiene éxito, devuelve el objeto Usuario con nombre de usuario, id y función prefilled (extraído de token).
	     * Si no tiene éxito (el token no es válido o no contiene todas las propiedades de usuario necesarias), simplemente devuelve null.
	     * 
	     * @param token  JWT token a parsear <br>
	     * ID claims.getId() <br>
	     * SUBJECT claims.getSubject()  <br>
	     * ISSUER claims.getIssuer() <br>
	     * EXPIRATION claims.getExpiration() <br>
	     * @return  El objeto de usuario extraido de token especificado o null si un token no es valido.
	     */
	    public static Usuario parseJWTComplex(String jwt) throws SegSucreException{
	        try {
				Claims claims = Jwts.parser()         
				   .setSigningKey(DatatypeConverter.parseBase64Binary(Constantes.CRYPTO_JWT))
				   .parseClaimsJws(jwt).getBody();
				return new Usuario(claims.getId(),claims.getId(),null,null,null,jwt,LanguageEnum.ES_EC,true,null);
			} catch (ExpiredJwtException e) {
				throw new SegSucreException(Constantes.ERROR_CODE_CUSTOM, "ERROR: ExpiredJwtException parseJWTComplex " + e.getMessage());
			} catch (UnsupportedJwtException e) {
				throw new SegSucreException(Constantes.ERROR_CODE_CUSTOM, "ERROR: UnsupportedJwtException parseJWTComplex " + e.getMessage());
			} catch (MalformedJwtException e) {
				throw new SegSucreException(Constantes.ERROR_CODE_CUSTOM, "ERROR: MalformedJwtException parseJWTComplex " + e.getMessage());
			} catch (IllegalArgumentException e) {
				throw new SegSucreException(Constantes.ERROR_CODE_CUSTOM, "ERROR: IllegalArgumentException parseJWTComplex " + e.getMessage());
			}catch (Exception e) {
				throw new SegSucreException(Constantes.ERROR_CODE_CUSTOM, "ERROR: Exception parseJWTComplex " + e.getMessage());
			}
	        
	    }
	    
	    
	

}
