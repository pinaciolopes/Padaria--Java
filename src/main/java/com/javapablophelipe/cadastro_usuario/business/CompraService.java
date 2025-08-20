package com.javapablophelipe.cadastro_usuario.business;

import com.javapablophelipe.cadastro_usuario.dto.CompraRequestDTO;
import com.javapablophelipe.cadastro_usuario.infrastructure.entitys.Compra;
import com.javapablophelipe.cadastro_usuario.infrastructure.entitys.Padaria;
import com.javapablophelipe.cadastro_usuario.infrastructure.entitys.Usuario;
import com.javapablophelipe.cadastro_usuario.infrastructure.repository.CompraRepository;
import com.javapablophelipe.cadastro_usuario.infrastructure.repository.PadariaRepository;
import com.javapablophelipe.cadastro_usuario.infrastructure.repository.UsuarioRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

import java.time.LocalDateTime;
import java.util.List;

@Service
@RequiredArgsConstructor

public class CompraService {

    private Double calcularValorTotal(List<Padaria> produtos) {
        return produtos.stream()
                .mapToDouble(Padaria::getPreco) // assumindo que Padaria tem um método getPreco()
                .sum();
    }

    private final CompraRepository compraRepository;
    private final UsuarioRepository usuarioRepository;
    private final PadariaRepository padariaRepository;

    public Compra criarCompraComDTO(CompraRequestDTO dto){
        Usuario usuario = usuarioRepository.findById(dto.getUsuarioId())
                .orElseThrow(() -> new RuntimeException("Usuário não encontrado"));

        List<Padaria> produtos = padariaRepository.findAllById(dto.getProdutosIds());

        Compra compra = Compra.builder()
                .usuario(usuario)
                .produtos(produtos)
                .dataCompra(LocalDateTime.now())
                .valorTotal(calcularValorTotal(produtos))
                .build();

        return compraRepository.save(compra);
    }


}
