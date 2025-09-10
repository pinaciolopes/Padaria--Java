package com.javapablophelipe.cadastro_usuario.controller;

import com.javapablophelipe.cadastro_usuario.business.UsuarioService;
import com.javapablophelipe.cadastro_usuario.infrastructure.entitys.Usuario;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/usuario")
@RequiredArgsConstructor
@CrossOrigin(origins = "https://padaria-java.onrender.com/usuario")

public class UsuarioController {

    private final UsuarioService usuarioService;

    @PostMapping
    public ResponseEntity <Void> salvarUsuario(@RequestBody Usuario usuario) {
            usuarioService.salvarUsuario(usuario);
            return ResponseEntity.ok().build();
    }

    @GetMapping
    public ResponseEntity <Usuario> buscarUsuarioPorCpf(@RequestParam String cpf) {
        return ResponseEntity.ok(usuarioService.buscarUsuarioPorCpf(cpf));
    }

    @DeleteMapping
    public ResponseEntity <Void> deletarUsuarioPorCpf(@RequestParam String cpf) {
        usuarioService.deletarUsuarioPorCpf(cpf);
        return ResponseEntity.ok().build();
    }

    @PutMapping
    public ResponseEntity <Void> atualizarUsuarioporCpf(@RequestParam String cpf,
                                                     @RequestBody Usuario usuario) {

        usuarioService.atualizarUsuarioporCpf(cpf, usuario);
        return ResponseEntity.ok().build();
    }
}

