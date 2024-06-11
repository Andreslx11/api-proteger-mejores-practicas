package med.voll.api.domain.infra.security;


import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.HttpSecurityBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;


/*
@Configuration esta anotacion es para que spring lo cargue de primero porque es una configuracion
para el servicio.
@EnableWebSecurity habalita modulo web security para esta class de configuracion,
para indicarle que este metodo securityFilterChain esta siendo utilizado para sobre escribir el
comportamiento de autenticacion que queremos
 */
@Configuration
@EnableWebSecurity
public class SecurityConfiguration {

    /*
    para evitar suplatacion de identidad
    CSRF (Cross-Site Request Forgery) es un tipo de ataque web en el que un usuario malicioso
    puede engañar a un usuario legítimo para que realice acciones no deseadas en una aplicación
    web a la que el usuario está autenticado.

    csrf() esta disable() por que estamos usando stateless usando token y ya nos protege cuantra
    ataques CSRF (Cross-Site Request Forgery), csrf() se usa para statefull,


    La anotación @Bean se utiliza para indicar que un método de una clase genera un objeto que
     debe ser administrado por el contenedor de Spring. Esto significa que Spring se encargará
     de crear e inyectar ese objeto en donde sea necesario.
     */


    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity httpSecurity) throws Exception {
        return httpSecurity.csrf(csrf -> csrf.disable())
                .sessionManagement(sess -> sess.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .build();
    }

/* asi es antes de la version de spring 3.1
    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity httpSecurity) throws Exception {
        return  httpSecurity.csrf().disable().sessionManagement()
                .sessionCreationPolicy(SessionCreationPolicy.STATELESS)
                .and().build();
    }

*/


    // Es para inyectar dependencia en AutenticacionController para que spring
    // lo pueda encontrar

    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration
                                                               authenticationConfiguration) throws Exception {

        return  authenticationConfiguration.getAuthenticationManager();
    }


    // passwordEncoder= codificador de contraseñascodificador de contraseñas
    /*
    BCryptPasswordEncoder es una implementación de la interfaz PasswordEncoder
    en Spring Security, que usa hash BCrypt
     */

    @Bean
    public PasswordEncoder passwordEncoder(){
        return new BCryptPasswordEncoder();
    }







}
