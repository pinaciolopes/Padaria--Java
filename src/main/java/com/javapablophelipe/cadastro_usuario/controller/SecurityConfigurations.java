package com.javapablophelipe.cadastro_usuario.config;

import com.javapablophelipe.cadastro_usuario.infrastructure.repository.UserRepository;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
public class SecurityConfigurations {

    private final UserRepository repository;

    public SecurityConfigurations(UserRepository repository) {
        this.repository = repository;
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration authenticationConfiguration) throws Exception {
        return authenticationConfiguration.getAuthenticationManager();
    }

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
                // Desabilita CSRF para testes e H2
                .csrf(csrf -> csrf.disable())

                // Permitir acesso a endpoints públicos
                .authorizeHttpRequests(auth -> auth
                        .requestMatchers("/auth/**").permitAll()
                        .requestMatchers("/usuario/**").permitAll()
                        .requestMatchers("/h2-console/**").permitAll()
                        .anyRequest().authenticated()
                )

                // Habilita frames do H2 console
                .headers(headers -> headers.frameOptions(frame -> frame.sameOrigin()))

                // Configura login padrão
                .formLogin()
                .permitAll()
                .and()
                .logout()
                .permitAll();

        return http.build();
    }
}
