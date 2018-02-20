package com.relative.core.util.web.security;

import java.io.IOException;

import javax.annotation.Priority;
import javax.servlet.http.HttpServletRequest;
import javax.ws.rs.NotAuthorizedException;
import javax.ws.rs.Priorities;
import javax.ws.rs.container.ContainerRequestContext;
import javax.ws.rs.container.ContainerRequestFilter;
import javax.ws.rs.core.Context;
import javax.ws.rs.core.HttpHeaders;
import javax.ws.rs.core.Response;
import javax.ws.rs.ext.Provider;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import ec.fin.segurossucre.core.exception.SegSucreException;
import ec.fin.segurossucre.core.util.main.Constantes;
import ec.fin.segurossucre.core.util.main.Usuario;

/**
 * Filtro para solicitudes enviadas a travez de Restful, que requiere
 * autenticacion y validacion Implementa la la inferace Qualifier
 * JWTTokenValidation
 * 
 * @author LUIS TAMAYO - RELATIVE ENGINE
 *
 */
@Provider
@JWTTokenValidation
@Priority(Priorities.AUTHENTICATION)
public class JWTCustomFilter implements ContainerRequestFilter {

	@Context
	private HttpServletRequest servletRequest;
	private static final Log log = LogFactory.getLog(JWTCustomFilter.class);

	public void filter(ContainerRequestContext requestContext) throws IOException {
		try {
			log.info("#### ingres a filtro JWTCustomFilter: ");
			String temporalToken= (String)servletRequest.getSession().getAttribute(Constantes.TEMPORAL_TOKEN_SESSION_ATTRIB);
			// Get the HTTP Authorization header from the request
			String authorizationHeader = requestContext.getHeaderString(HttpHeaders.AUTHORIZATION);
			log.info("#### authorizationHeader : " + authorizationHeader);
			if (authorizationHeader != null && authorizationHeader.startsWith(Constantes.KEYHEADER_FIRST_LOGIN_JWT)) {
				log.info("#### authorizationHeader firstlogin : ");
				String firstLoginKey = authorizationHeader.substring(Constantes.KEYHEADER_FIRST_LOGIN_JWT.length())
						.trim();
				log.info("#### authorizationHeader firstlogin key : " + firstLoginKey);
				log.info("#### authorizationHeader firstlogin temporal token : " + temporalToken);
				//if (!firstLoginKey.trim().equalsIgnoreCase(Constantes.SECURITY_KEY_FIRST_LOGIN)) {
				if (!firstLoginKey.trim().equalsIgnoreCase(temporalToken)) {
					log.info("#### ERROR en first login");
					throw new NotAuthorizedException("Authorization header must be provided");
				}
				return;
			}
			// Check if the HTTP Authorization header is present and formatted correctly
			if (authorizationHeader == null || !authorizationHeader.startsWith(Constantes.KEYHEADER_JWT)) {
				log.info("#### invalid authorizationHeader : " + authorizationHeader);
				throw new NotAuthorizedException("Authorization header must be provided");
			}
			// Extract the token from the HTTP Authorization header
			String token = authorizationHeader.substring(Constantes.KEYHEADER_JWT.length()).trim();
			log.info("#### TOKEN EXTRAIDO : " + token);
			Usuario user = JwtUtil.parseJWTComplex(token);
			// Validate the token
			log.info("#### usairio es id : " + user.getId());
			log.info("#### usairio es nombre : " + user.getNombre());
		} catch (SegSucreException e) {
			log.info("#### RelativeException invalid token : " + e.getMessage());
			requestContext.abortWith(Response.status(Response.Status.UNAUTHORIZED).build());
		} catch (Exception e) {
			log.info("#### Exception invalid token : " + e.getMessage());
			requestContext.abortWith(Response.status(Response.Status.UNAUTHORIZED).build());
		}

	}

}
