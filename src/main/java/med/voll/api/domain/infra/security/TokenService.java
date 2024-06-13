package med.voll.api.domain.infra.security;


import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.JWTCreationException;
import med.voll.api.domain.usuario.Usuario;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.time.LocalDateTime;
import java.time.ZoneOffset;

@Service
public class TokenService {

   /* para consumir la variable que escribimos en properties (vaiable de entorno),
      se usa la anotaccion @Value  y se pasa la propiedad del propertiespara que obtenga
      el valor esa variable */
    @Value("${api-proteger-mejores-practicas.security.secret}")
    private String apiSecret;



    // recordar imporetante el metodo debe ser llamado en AuntenticacionController

    public String generarToken(Usuario usuario){
        // codigo fue copiado del repositorio de json web token ath0
        // se modico cosas
        try {
          // se comento por el instructor prefirio usar un metodo mas sencillo
         //Algorithm algorithm = Algorithm.RSA256(rsaPublicKey, rsaPrivateKey);
            Algorithm algorithm = Algorithm.HMAC256(apiSecret);
           return  JWT.create()
                    .withIssuer("voll med")
                   .withSubject(usuario.getLogin())
                   .withClaim("id", usuario.getId())
                   .withExpiresAt(generarFechaExperiracion())
                    .sign(algorithm);
        } catch (JWTCreationException exception){
            throw new RuntimeException();
            // Invalid Signing configuration / Couldn't convert Claims.
        }
    }

    private Instant generarFechaExperiracion(){
        return LocalDateTime.now().plusHours(2).toInstant(ZoneOffset.of("-05:00"));
    }
}
