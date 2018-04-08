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

import static com.auth0.samples.authapi.security.SecurityConstants.EXPIRATION_TIME;
import static com.auth0.samples.authapi.security.SecurityConstants.HEADER_STRING;
import static com.auth0.samples.authapi.security.SecurityConstants.SECRET;
import static com.auth0.samples.authapi.security.SecurityConstants.TOKEN_PREFIX;

import java.io.IOException;
import java.util.Date;
import java.util.HashSet;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import com.auth0.samples.authapi.exception.AccessDeniedException;
import com.auth0.samples.authapi.user.ApplicationUser;
import com.fasterxml.jackson.databind.ObjectMapper;

import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;

/**
 * This filter extracts the user's credentials from the request to attempt to use it to authenticate
 * the user through the {@link AuthenticationManager}. Since it has been successful authenticated,
 * the filter will generate the JWT token and will add it into the header.
 *
 * @author rodrigo
 */
public class JwtAuthenticationFilter extends UsernamePasswordAuthenticationFilter {
    
    private AuthenticationManager authenticationManager;

    public JwtAuthenticationFilter(AuthenticationManager authenticationManager) {
        this.authenticationManager = authenticationManager;
    }

    @Override
    public Authentication attemptAuthentication(HttpServletRequest request,
                                                HttpServletResponse response) {
        try {
            ApplicationUser credentials = (new ObjectMapper()).readValue(request.getInputStream(), ApplicationUser.class);
            return this.authenticationManager.authenticate(
               new UsernamePasswordAuthenticationToken(credentials.getUsername(),
                                                       credentials.getPassword(),
                                                       new HashSet<>())
            );
        } catch (IOException e) {
            throw new AccessDeniedException(e.getMessage(), e);
        }
    }

    @Override
    protected void successfulAuthentication(HttpServletRequest request,
                                            HttpServletResponse response,
                                            FilterChain chain,
                                            Authentication auth) throws IOException, ServletException {
        String token = Jwts.builder()
            .setSubject(((User) auth.getPrincipal()).getUsername())
            .setExpiration(new Date(System.currentTimeMillis() + EXPIRATION_TIME))
            .signWith(SignatureAlgorithm.HS512, SECRET)
            .compact();
        
        response.addHeader(HEADER_STRING, TOKEN_PREFIX + token);
    }
}
