package com.javapablophelipe.cadastro_usuario.business;


import com.javapablophelipe.cadastro_usuario.infrastructure.entitys.Usuario;
import com.javapablophelipe.cadastro_usuario.infrastructure.repository.UsuarioRepository;
import org.springframework.stereotype.Service;

@Service
public class UsuarioService {

    private final UsuarioRepository repository;

    public UsuarioService(UsuarioRepository repository) {
        this.repository = repository;
    }

    public void salvarUsuario(Usuario usuario) {
        repository.saveAndFlush(usuario);
    }
    public Usuario buscarUsuarioPorCpf(String cpf) {
        return repository.findByCpf(cpf).orElseThrow(
                ()-> new RuntimeException("Cpf não encontrado")
        );
    }

    public void deletarUsuarioPorCpf(String cpf) {
        repository.deleteByCpf(cpf);
    }

    public void atualizarUsuarioporCpf(String cpf, Usuario usuario) {
        Usuario usuarioEntity = repository.findByCpf(cpf).orElseThrow(
                ()-> new RuntimeException("Usuario não encontrado")
        );
        Usuario usuarioAtualizado = Usuario.builder()
                .id(usuarioEntity.getId())
                .nome(usuario.getNome()!=null ? usuario.getNome():
                        usuarioEntity.getNome())
                .cpf(usuarioEntity.getCpf())
                .email(usuario.getEmail()!=null ? usuario.getEmail() :
                        usuarioEntity.getEmail())
                .dataNascimento(usuario.getDataNascimento()!= null ? usuario.getDataNascimento():
                        usuarioEntity.getDataNascimento())
                .telefone(usuario.getTelefone()!= null ? usuario.getTelefone() :
                        usuarioEntity.getTelefone()).build();
        repository.saveAndFlush(usuarioAtualizado);
    }
}
