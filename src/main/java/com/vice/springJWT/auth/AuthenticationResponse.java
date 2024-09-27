package com.vice.springJWT.auth;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data //build getters and setters
@Builder //build constructors easily
@AllArgsConstructor
@NoArgsConstructor
public class AuthenticationResponse {
	
	private String token;

}
