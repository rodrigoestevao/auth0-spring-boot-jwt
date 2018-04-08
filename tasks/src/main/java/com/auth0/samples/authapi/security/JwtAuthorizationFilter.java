/***************************************************************************************************
 * Software License Agreement (New BSD License)
 ***************************************************************************************************
 * Copyright (c) 2018 Rodrigo Estevao <rodrigoestevao@yahoo.com>
 *
 * Redistribution  and  use  in source and binary forms, with or without modification, are permitted
 * provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice, this list of conditions
 *    and the following disclaimer.
 * 2. Redistributions  in  binary  form  must  reproduce  the  above  copyright notice, this list of
 *    conditions  and  the following disclaimer in the documentation and/or other materials provided
 *    with the distribution.
 * 3. Neither  the  name  of  the  copyright holder nor the names of its contributors may be used to
 *    endorse  or  promote  products  derived  from  this  software  without  specific prior written
 *    permission.
 *
 * THIS  SOFTWARE  IS  PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR
 * IMPLIED  WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND
 * FITNESS  FOR  A  PARTICULAR  PURPOSE  ARE  DISCLAIMED.  IN NO EVENT SHALL THE COPYRIGHT HOLDER OR
 * CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA,  OR  PROFITS;  OR  BUSINESS  INTERRUPTION)  HOWEVER  CAUSED AND ON ANY THEORY OF LIABILITY,
 * WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY
 * WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */
package com.auth0.samples.authapi.security;


import static com.auth0.samples.authapi.security.SecurityConstants.HEADER_STRING;
import static com.auth0.samples.authapi.security.SecurityConstants.SECRET;
import static com.auth0.samples.authapi.security.SecurityConstants.TOKEN_PREFIX;
import java.io.IOException;
import java.util.HashSet;
import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;

import com.auth0.samples.authapi.exception.InvalidHeaderException;

import io.jsonwebtoken.Jwts;

/**
 * @author rodrigo
 *
 */
public class JwtAuthorizationFilter extends BasicAuthenticationFilter{
	
	private static final Logger LOGGER = LoggerFactory.getLogger(JwtAuthorizationFilter.class);

    /**
     * Constructor
     *
     * @param authenticationManager
     */
    public JwtAuthorizationFilter(AuthenticationManager authenticationManager) {
        super(authenticationManager);
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain chain) throws IOException, ServletException {
        String header = request.getHeader(HEADER_STRING);
        
        if (header == null || !header.startsWith(TOKEN_PREFIX)) {
        	throw new InvalidHeaderException(HEADER_STRING);
        } else {
            UsernamePasswordAuthenticationToken authentication = this.getAuthentication(request);
            SecurityContextHolder.getContext().setAuthentication(authentication);
        }
        chain.doFilter(request, response);
    }

    private UsernamePasswordAuthenticationToken getAuthentication(HttpServletRequest request) {
        UsernamePasswordAuthenticationToken token = null;

        String header = request.getHeader(HEADER_STRING);
        
        if (header != null) {
            // parse the token
            String user = Jwts.parser()
                .setSigningKey(SECRET)
                .parseClaimsJws(header.replace(TOKEN_PREFIX, ""))
                .getBody()
                .getSubject();

            if (user != null) {
                token = new UsernamePasswordAuthenticationToken(user, null, new HashSet<>());
            } else {
            	LOGGER.error("The authentication token does not have a valid user.");
            }
        } else {
        	LOGGER.error("The {} header is not present or is invalid", HEADER_STRING);
        }
        return token;
    }
}
