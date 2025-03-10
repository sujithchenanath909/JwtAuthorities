package in.sujithchenanath.jwtAuthorities;


import java.util.Base64;
import java.util.Collection;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwt;
import io.jsonwebtoken.JwtParser;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;

public class JwtClaimsParser {
	
	Jwt<?,?> jwtObject;
	public JwtClaimsParser(String jwt,String secretKey) {
		
		this.jwtObject = parseJwt(jwt, secretKey);
	}
	
	Jwt<?,?> parseJwt(String jwt,String secretKeyToken){
		
		byte[] secretKeyBytes = Base64.getEncoder().encode(secretKeyToken.getBytes());
		SecretKey secretKey = new SecretKeySpec(secretKeyBytes, SignatureAlgorithm.HS512.getJcaName());
		JwtParser jwtParser = Jwts.parser().setSigningKey(secretKey).build();
		return jwtParser.parse(jwt);
	}
	
	public Collection<? extends GrantedAuthority> getUserAuthorities(){
	Collection<Map<String,String>> scopes =	((Claims)jwtObject.getBody()).get("scope",List.class);
		return scopes.stream()
				.map(scopeMap -> new SimpleGrantedAuthority(scopeMap.get("authority")))
				.collect(Collectors.toList());
	}
	
	public String getJwtSubject() {
		return ((Claims)jwtObject.getBody()).getSubject();
	}
}
