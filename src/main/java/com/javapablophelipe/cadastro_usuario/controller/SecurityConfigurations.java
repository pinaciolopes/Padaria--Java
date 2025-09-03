package com.javapablophelipe.cadastro_usuario.controller;

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

    // Encoder para senhas
    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    // Gerenciador de autenticação
    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration authenticationConfiguration) throws Exception {
        return authenticationConfiguration.getAuthenticationManager();
    }

    // Configurações de segurança
    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
                // ⚠️ Desabilite CSRF só se for API REST (senão, remova essa linha em produção)
                .csrf(csrf -> csrf.disable())

                // Regras de autorização
                .authorizeHttpRequests(auth -> auth
                        .requestMatchers("/", "/index", "/home").permitAll() // páginas públicas
                        .requestMatchers("/auth/**").permitAll()             // endpoints de auth
                        .requestMatchers("/usuario/**").permitAll()          // cadastro de usuário
                        .requestMatchers("/h2-console/**").permitAll()       // H2 console
                        .anyRequest().authenticated()                        // resto exige login
                )

                // Permitir o uso do H2-console
                .headers(headers -> headers.frameOptions(frame -> frame.sameOrigin()))

                // Configuração do login
                .formLogin(form -> form
                        .loginPage("/auth/login")            // página de login customizada
                        .defaultSuccessUrl("/home", true)    // redireciona após login
                        .permitAll()
                )

                // Configuração do logout
                .logout(logout -> logout
                        .logoutUrl("/auth/logout")
                        .logoutSuccessUrl("/")               // volta pra página inicial
                        .permitAll()
                );

        return http.build();
    }
}
