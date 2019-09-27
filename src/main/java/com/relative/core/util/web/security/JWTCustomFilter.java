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

import com.relative.core.exception.RelativeException;
import com.relative.core.util.main.Constantes;
import com.relative.core.util.main.Usuario;
import com.relative.core.util.web.security.JWTTokenValidation;
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
			log.debug("#### ingres a filtro JWTCustomFilter: ");
			log.debug("####============> SESSION ID: " + servletRequest.getSession().getId());
			
			// Get the HTTP Authorization header from the request
			String authorizationHeader = requestContext.getHeaderString(HttpHeaders.AUTHORIZATION);
			log.debug("#### authorizationHeader : " + authorizationHeader);
			if (authorizationHeader != null && authorizationHeader.startsWith(Constantes.KEYHEADER_FIRST_LOGIN_JWT)) {
				log.debug("#### authorizationHeader firstlogin : ");
				String temporalToken= (String)servletRequest.getSession().getAttribute(Constantes.TEMPORAL_TOKEN_SESSION_ATTRIB);
				String firstLoginKey = authorizationHeader.substring(Constantes.KEYHEADER_FIRST_LOGIN_JWT.length()).trim();
				log.debug("#### authorizationHeader firstlogin key : " + firstLoginKey);
				log.debug("#### authorizationHeader firstlogin temporal token : " + temporalToken);
				if (!firstLoginKey.trim().equalsIgnoreCase(temporalToken)) {
					log.debug("#### ERROR en first login");
					throw new NotAuthorizedException("CABECERA DE AUTORIZACION DEBE SER PROVISTA PARA PRIMER LOGIN, GENERE TOKEN TEMPORAL");
				}
					
				return;
			}
			// Check if the HTTP Authorization header is present and formatted correctly
			if (authorizationHeader == null || !authorizationHeader.startsWith(Constantes.KEYHEADER_JWT)) {
				log.debug("#### invalid authorizationHeader : " + authorizationHeader);
				throw new NotAuthorizedException("CABECERA DE AUTORIZACION DEBE SER PROVISTA PARA VALIDACION DE TOKEN");
			}
			// Extract the token from the HTTP Authorization header
			String token = authorizationHeader.substring(Constantes.KEYHEADER_JWT.length()).trim();
			log.debug("#### TOKEN EXTRAIDO : " + token);
			Usuario user = JwtUtil.parseJWTComplex( token );
			log.debug( "==========>>>comparo usuario token: " + user.getId() + " contra usuario en session " +
					servletRequest.getSession().getAttribute( Constantes.USER_SESSION_ATTRIB ) );
			// Validate the token
			/*if(!user.getId().equalsIgnoreCase( String.valueOf(
					servletRequest.getSession().getAttribute( Constantes.USER_SESSION_ATTRIB )))) {
				throw new RelativeException( Constantes.ERROR_CODE_CUSTOM, "ERROR EN LOGIN, EL USUARIO ENVIADO EN EL TOKEN NO CORRESPONDE AL USUARIO EN SESSION" );
			}*/
			
			log.debug("#### usairio es id : " + user.getId());
			log.debug("#### usairio es nombre : " + user.getNombre());
		} catch (RelativeException e) {
			log.debug("#### RelativeException invalid token : " + e.getMessage());
			requestContext.abortWith(Response.status(Response.Status.UNAUTHORIZED).build());
		} catch (Exception e) {
			log.debug("#### Exception invalid token : " + e.getMessage());
			requestContext.abortWith(Response.status(Response.Status.UNAUTHORIZED).build());
		}

	}
	
	

}
