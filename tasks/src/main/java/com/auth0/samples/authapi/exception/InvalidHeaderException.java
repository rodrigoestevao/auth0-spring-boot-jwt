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
package com.auth0.samples.authapi.exception;

import java.io.IOException;

import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.ResponseStatus;

/**
 * @author rodrigo
 *
 */
@ResponseStatus(value = HttpStatus.BAD_REQUEST)
public class InvalidHeaderException extends IOException {

	private static final long serialVersionUID = -2600592720431537221L;

	private static final String TEMPLATE_MSG = "The {} header is not present or is invalid";

	public InvalidHeaderException(String header) {
		super(TEMPLATE_MSG.replace("{}", header));
	}

	public InvalidHeaderException(String header, Throwable cause) {
		super(TEMPLATE_MSG.replace("{}", header), cause);
	}
}
