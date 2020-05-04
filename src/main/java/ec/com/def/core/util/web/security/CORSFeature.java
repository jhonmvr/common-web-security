package ec.com.def.core.util.web.security;

import javax.ws.rs.core.Feature;
import javax.ws.rs.core.FeatureContext;
import javax.ws.rs.ext.Provider;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.jboss.resteasy.plugins.interceptors.CorsFilter;

@Provider
public class CORSFeature implements Feature {

	private static final Log log = LogFactory.getLog(CORSFeature.class);
	

	/**
	 * {@code
	 * codigo removido
	 * //responseContext.getHeaders().add("Access-Control-Allow-Origin", "*");
 	    //responseContext.getHeaders().add("Access-Control-Allow-Headers", "origin, content-type, accept, authorization");
 	    //responseContext.getHeaders().add("Access-Control-Allow-Credentials", "true");
 	    //responseContext.getHeaders().add("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS, HEAD");
 	    //responseContext.getHeaders().add("Access-Control-Max-Age", "1209600"); 
	 * }
	 * 
	 */
    public boolean configure(FeatureContext context) {
    	log.info("===>> entra a configure cors feature");
    	CorsFilter corsFilter = new CorsFilter();
        corsFilter.getAllowedOrigins().add("*");
        corsFilter.setAllowCredentials( Boolean.TRUE );
        corsFilter.setAllowedMethods("OPTIONS, GET, POST, DELETE, PUT, HEAD, PATCH");
        corsFilter.setAllowedHeaders("origin, content-type, accept, authorization,x-requested-with");
        
        
        context.register(corsFilter);
        return true;
    }  
}