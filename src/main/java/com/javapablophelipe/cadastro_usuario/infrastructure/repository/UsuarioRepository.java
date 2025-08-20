package com.javapablophelipe.cadastro_usuario.infrastructure.repository;



import com.javapablophelipe.cadastro_usuario.infrastructure.entitys.Usuario;
import jakarta.transaction.Transactional;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;


public interface UsuarioRepository extends JpaRepository<Usuario, Long> {

    Optional<Usuario> findByCpf(String cpf);
    @Transactional
    void deleteByCpf(String cpf);
}
