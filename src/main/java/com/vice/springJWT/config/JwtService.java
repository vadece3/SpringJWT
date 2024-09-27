package com.vice.springJWT.config;

import java.security.Key;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Function;

import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;

@Service
public class JwtService {
	
	private static final String SECRET_KEY = "92c8f77dd876504e0fc6aeb9ec359ffdcd31c2721b662cc4716a21fc1a3a59a203344fa44e42a32fa5eddfcc233a5095bc42e41025e3938f7bedba24ed6a3f67480b07ddb330354e56dde4db7ffb061e844440aed42ef032684197f4de890f27ecc17987fa5c0abde12b9da71ee02eef7787100ddcb2be1d0876d17d55c1b8efe204ca739e9cef4583ebb15dacf715e1cb239e3876c030241ddda13c81206986997a63162b3d2d02c45366589c1c66df04d4bd00df73764be6b626fe749540886de69f5497ac2a04ca3633c5217b533989b115fef0c268cbc6a8414a12f058530d04dcfaeed98b9088334b1ed3a0061d4cb5409e3d1a979d2603b38139ac2215";

	public String extractUsername(String token) {
		return extractClaim(token, Claims::getSubject);
	}
	
	//generate a token from only UserDetails
	public String generateToken(UserDetails userDetails) {
		return generateToken(new HashMap<>(), userDetails);
	}
	
	//generate a token from extraClaims
	public String generateToken(
			Map<String, Object> extraClaims,
			UserDetails userDetails) {
		return Jwts.
				builder().
				setClaims(extraClaims).
				setSubject(userDetails.getUsername()).
				setIssuedAt(new Date(System.currentTimeMillis())).
				setExpiration(new Date(System.currentTimeMillis() + 100 * 60 * 24)).
				signWith(getSignInKey(), SignatureAlgorithm.HS256).
				compact();
	}
	
	//method to validate a token
	public boolean isTokenValid(String token, UserDetails userDetails) {
		final String username = extractUsername(token);
		return (username.equals(userDetails.getUsername())) && !isTokenExpired(token);
	}
	
	private boolean isTokenExpired(String token) {
		return extractExpiration(token).before(new Date());
	}

	private Date extractExpiration(String token) {
		return extractClaim(token, Claims::getExpiration);
	}

	//extract all claims(payload) from token
	public <T> T extractClaim(String token, Function<Claims, T> claimsResolver) {
		final Claims claims = extractAllClaims(token);
		return claimsResolver.apply(claims);
	}
	
	private Claims extractAllClaims(String token) {
		return Jwts.
				parserBuilder().
				setSigningKey(getSignInKey()).
				build().
				parseClaimsJws(token).
				getBody();
	}

	private Key getSignInKey() {
		byte[] keyBytes = Decoders.BASE64.decode(SECRET_KEY);
		return Keys.hmacShaKeyFor(keyBytes);
	}

}
