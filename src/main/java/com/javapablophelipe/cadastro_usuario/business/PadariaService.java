package com.javapablophelipe.cadastro_usuario.business;

import com.javapablophelipe.cadastro_usuario.infrastructure.entitys.Padaria;
import com.javapablophelipe.cadastro_usuario.infrastructure.repository.PadariaRepository;
import org.springframework.stereotype.Service;

@Service
public class PadariaService {

    private final PadariaRepository repository;

    public PadariaService(PadariaRepository repository) {
        this.repository = repository;
    }

    public void cadastrarProduto(Padaria padaria) {
        repository.saveAndFlush(padaria);
    }

    public Padaria buscarProdutoPorId(Long id) {
        return repository.findById(id).orElseThrow(
                () -> new RuntimeException("Produto nao encontrado")
        );
    }

    public void deletarProdutoPorId(Long id) {
        repository.deleteById(id);
    }

    public void atualizarProdutoPorId(Long id, Padaria padaria) {
        Padaria padariaEntity = repository.findById(id).orElseThrow(
                () -> new RuntimeException("Produto nao encontrado")
        );
        Padaria produtoAtualizado = Padaria.builder()
                .id(padaria.getId() != null ? padaria.getId() :
                        padariaEntity.getId())
                .nome(padaria.getNome() != null ? padaria.getNome() :
                        padariaEntity.getNome())
                .preco(padaria.getPreco() != null ? padaria.getPreco() :
                        padariaEntity.getPreco()).build();
        repository.saveAndFlush(produtoAtualizado);
    }
}
