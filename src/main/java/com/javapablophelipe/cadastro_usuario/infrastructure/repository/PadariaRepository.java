package com.javapablophelipe.cadastro_usuario.infrastructure.repository;

import com.javapablophelipe.cadastro_usuario.infrastructure.entitys.Padaria;
import jakarta.transaction.Transactional;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;
import java.util.Optional;

public interface PadariaRepository extends JpaRepository<Padaria, Long> {
    Optional<Padaria> findById(Long id);
    @Transactional
    void deleteById(Long id);

}
